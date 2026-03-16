"""
tests/test_cve_lookup.py
========================
Unit tests for tools/cve_lookup.py.

Network-dependent tests are skipped in offline / CI environments.
Pure parsing tests run in all environments.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from tools.cve_lookup import CVELookup, CVEEntry


@pytest.fixture
def lookup():
    return CVELookup()


class TestCVEEntry:
    """Tests for the CVEEntry data class (no network needed)."""

    def test_str_representation(self):
        entry = CVEEntry(
            cve_id="CVE-2021-44228",
            description="Log4Shell remote code execution vulnerability.",
            severity="CRITICAL",
            cvss_score=10.0,
            cvss_version="3.1",
            published="2021-12-10",
            last_modified="2022-01-01",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            cwe_ids=["CWE-502"],
        )
        text = str(entry)
        assert "CVE-2021-44228" in text
        assert "CRITICAL" in text
        assert "10.0" in text
        assert "CWE-502" in text

    def test_parse_vulnerability_minimal(self):
        """Test _parse_vulnerability with a minimal NVD JSON structure."""
        vuln_json = {
            "cve": {
                "id": "CVE-2023-12345",
                "descriptions": [
                    {"lang": "en", "value": "A test vulnerability."}
                ],
                "metrics": {},
                "published": "2023-01-01T00:00:00.000",
                "lastModified": "2023-06-01T00:00:00.000",
                "references": [],
                "weaknesses": [],
            }
        }
        entry = CVELookup._parse_vulnerability(vuln_json)
        assert entry.cve_id == "CVE-2023-12345"
        assert entry.description == "A test vulnerability."
        assert entry.severity == "UNKNOWN"
        assert entry.cvss_score == 0.0

    def test_parse_vulnerability_with_cvss31(self):
        """Test _parse_vulnerability with CVSS 3.1 metrics."""
        vuln_json = {
            "cve": {
                "id": "CVE-2023-99999",
                "descriptions": [{"lang": "en", "value": "High severity issue."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "baseSeverity": "HIGH",
                            "cvssData": {
                                "baseScore": 8.8,
                                "version": "3.1",
                                "baseSeverity": "HIGH",
                            },
                        }
                    ]
                },
                "published": "2023-03-15T00:00:00.000",
                "lastModified": "2023-04-01T00:00:00.000",
                "references": [{"url": "https://example.com/advisory"}],
                "weaknesses": [
                    {"description": [{"value": "CWE-79"}]}
                ],
            }
        }
        entry = CVELookup._parse_vulnerability(vuln_json)
        assert entry.severity == "HIGH"
        assert entry.cvss_score == 8.8
        assert entry.cvss_version == "3.1"
        assert "CWE-79" in entry.cwe_ids
        assert "https://example.com/advisory" in entry.references
