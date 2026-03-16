"""
tools/cve_lookup.py
===================
Query the NIST National Vulnerability Database (NVD) REST API v2 to look up
CVE information by ID or keyword search.

Official API documentation: https://nvd.nist.gov/developers/vulnerabilities

Rate limits:
  - Without API key: 5 requests / 30 s rolling window
  - With API key:    50 requests / 30 s rolling window

Set NVD_API_KEY in your .env file to increase the rate limit.
"""

import os
import time
from dataclasses import dataclass, field
from typing import List, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY: Optional[str] = os.getenv("NVD_API_KEY") or None

# Seconds to wait between requests when no API key is present
_RATE_LIMIT_SLEEP = 6


@dataclass
class CVEEntry:
    """Simplified representation of a single CVE record."""
    cve_id: str
    description: str
    severity: str               # CRITICAL / HIGH / MEDIUM / LOW / NONE / UNKNOWN
    cvss_score: float           # 0.0 – 10.0
    cvss_version: str           # e.g. "3.1"
    published: str              # ISO date string
    last_modified: str
    references: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        return (
            f"{'─' * 60}\n"
            f"CVE ID    : {self.cve_id}\n"
            f"Severity  : {self.severity} (CVSS {self.cvss_version}: {self.cvss_score})\n"
            f"Published : {self.published}\n"
            f"CWE       : {', '.join(self.cwe_ids) or 'N/A'}\n"
            f"Description:\n  {self.description[:500]}\n"
            f"References:\n" +
            "\n".join(f"  - {r}" for r in self.references[:3]) +
            "\n"
        )


class CVELookup:
    """
    Client for the NVD CVE API.

    Usage:
        lookup = CVELookup()

        # Look up a specific CVE
        cve = lookup.get_cve("CVE-2021-44228")

        # Keyword search
        results = lookup.search("log4j remote code execution", max_results=5)
    """

    def __init__(self, api_key: Optional[str] = NVD_API_KEY):
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers["apiKey"] = api_key

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """
        Fetch a specific CVE by its ID (e.g. "CVE-2021-44228").

        Returns None if the CVE is not found.
        """
        params = {"cveId": cve_id}
        data = self._request(params)
        if not data:
            return None
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        return self._parse_vulnerability(vulns[0])

    def search(self, keyword: str, max_results: int = 10) -> List[CVEEntry]:
        """
        Search CVEs by keyword.

        Parameters
        ----------
        keyword:     Search term (e.g. "buffer overflow openssl").
        max_results: Maximum number of results to return (max 2000 per NVD docs).
        """
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results, 2000),
        }
        data = self._request(params)
        if not data:
            return []
        return [
            self._parse_vulnerability(v)
            for v in data.get("vulnerabilities", [])
        ]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _request(self, params: dict) -> Optional[dict]:
        """
        Send a request to the NVD API with basic error handling and
        rate-limit back-off.
        """
        if not self.api_key:
            # Without an API key we must stay within 5 req / 30 s
            time.sleep(_RATE_LIMIT_SLEEP)

        try:
            resp = self.session.get(NVD_BASE_URL, params=params, timeout=15)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.HTTPError as exc:
            print(f"[CVELookup] HTTP error: {exc}")
        except requests.exceptions.ConnectionError:
            print("[CVELookup] Could not reach NVD API – check your internet connection.")
        except requests.exceptions.Timeout:
            print("[CVELookup] Request to NVD API timed out.")
        return None

    @staticmethod
    def _parse_vulnerability(vuln: dict) -> CVEEntry:
        """Extract the fields we care about from the raw NVD JSON structure."""
        cve = vuln.get("cve", {})

        # CVE ID
        cve_id = cve.get("id", "UNKNOWN")

        # English description
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # CVSS score and severity
        severity = "UNKNOWN"
        cvss_score = 0.0
        cvss_version = "N/A"
        metrics = cve.get("metrics", {})
        # Try CVSS v3.1 first, then v3.0, then v2.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_data = m.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = m.get("baseSeverity") or cvss_data.get("baseSeverity", "UNKNOWN")
                cvss_version = cvss_data.get("version", "N/A")
                break

        # Published / modified dates
        published = cve.get("published", "")[:10]
        last_modified = cve.get("lastModified", "")[:10]

        # References (URLs)
        references = [
            r.get("url", "")
            for r in cve.get("references", [])
            if r.get("url")
        ]

        # CWE identifiers
        cwe_ids: List[str] = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    cwe_ids.append(value)

        return CVEEntry(
            cve_id=cve_id,
            description=description,
            severity=severity.upper(),
            cvss_score=cvss_score,
            cvss_version=cvss_version,
            published=published,
            last_modified=last_modified,
            references=references,
            cwe_ids=cwe_ids,
        )
