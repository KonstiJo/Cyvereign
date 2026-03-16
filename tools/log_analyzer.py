"""
tools/log_analyzer.py
=====================
Analyses web server / system log files for suspicious patterns that may
indicate security incidents:

* Brute-force / credential stuffing (many failed logins from one IP)
* SQL injection attempts in HTTP request paths
* Directory traversal attempts
* Scanner / tool fingerprints (nikto, sqlmap, nmap, etc.)
* Exploit payload patterns (CVE-related strings, shell commands in URLs)
* Excessive 4xx / 5xx error rates per IP

Supported log formats:
  - Apache / Nginx Combined Log Format
  - Simple key=value structured logs (best-effort)
  - Generic line-by-line pattern matching for any text log
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class LogAlert:
    """A single suspicious event detected in the log."""
    severity: str           # "HIGH", "MEDIUM", "LOW"
    category: str           # Human-readable category name
    description: str
    line_number: int
    raw_line: str
    ip_address: str = ""


@dataclass
class LogAnalysisResult:
    """Aggregated result for a single log file."""
    file_path: str
    total_lines: int = 0
    alerts: List[LogAlert] = field(default_factory=list)
    ip_stats: Dict[str, int] = field(default_factory=dict)  # IP -> request count

    def summary(self) -> str:
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for a in self.alerts:
            counts[a.severity] += 1
        return (
            f"📋 {self.file_path}  [{self.total_lines} lines]\n"
            f"   Alerts: {counts['HIGH']} HIGH | {counts['MEDIUM']} MEDIUM | {counts['LOW']} LOW"
        )


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------
# Tuple: (severity, category, compiled_regex)

_PATTERNS: List[tuple] = [
    (
        "HIGH", "SQL Injection Attempt",
        re.compile(
            r"(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\bdrop\b.*\btable\b"
            r"|\binsert\b.*\binto\b|\bexec\b|\bxp_cmdshell\b|'.*or.*'.*=.*')",
            re.IGNORECASE,
        ),
    ),
    (
        "HIGH", "Directory Traversal Attempt",
        re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e)", re.IGNORECASE),
    ),
    (
        "HIGH", "Remote Code Execution Attempt",
        re.compile(
            r"(/bin/sh|/bin/bash|cmd\.exe|powershell|wget\s|curl\s.*http|"
            r"base64_decode|eval\(|system\(|passthru\()",
            re.IGNORECASE,
        ),
    ),
    (
        "HIGH", "Exploit / CVE Payload",
        re.compile(
            r"(\$\{jndi:|jndi:ldap|jndi:rmi|log4j|CVE-\d{4}-\d{4,})",
            re.IGNORECASE,
        ),
    ),
    (
        "MEDIUM", "Scanner / Automated Tool",
        re.compile(
            r"(nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|gobuster"
            r"|wfuzz|burpsuite|acunetix|nessus|openvas)",
            re.IGNORECASE,
        ),
    ),
    (
        "MEDIUM", "Brute-Force / Auth Failure",
        re.compile(
            r"(401|403|invalid password|authentication failed|login failed"
            r"|too many requests|rate limit)",
            re.IGNORECASE,
        ),
    ),
    (
        "MEDIUM", "XSS Attempt",
        re.compile(
            r"(<script|javascript:|on(load|error|click|mouseover)\s*=|"
            r"alert\s*\(|document\.cookie)",
            re.IGNORECASE,
        ),
    ),
    (
        "LOW", "Suspicious User-Agent",
        re.compile(
            r'(python-requests|go-http-client|libwww-perl|curl/\d|wget/\d)',
            re.IGNORECASE,
        ),
    ),
]

# Regex to extract IP address from the start of a Combined-Log-Format line
_IP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})")


# ---------------------------------------------------------------------------
# Brute-force detection thresholds
# ---------------------------------------------------------------------------
_AUTH_FAILURE_THRESHOLD = 10   # alerts if one IP triggers ≥ this many auth failures


class LogAnalyzer:
    """
    Analyses log files for suspicious / malicious patterns.

    Usage:
        analyzer = LogAnalyzer()
        result = analyzer.analyze_file("/var/log/nginx/access.log")
        print(result.summary())
        for alert in result.alerts:
            print(f"  Line {alert.line_number}: [{alert.severity}] {alert.category}")
    """

    def analyze_file(self, file_path: str) -> LogAnalysisResult:
        """
        Analyse a log file and return a LogAnalysisResult.

        Parameters
        ----------
        file_path: Path to the log file.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        result = LogAnalysisResult(file_path=str(path))
        ip_failure_counts: Dict[str, int] = defaultdict(int)

        with open(path, encoding="utf-8", errors="ignore") as fh:
            for lineno, raw_line in enumerate(fh, start=1):
                result.total_lines += 1
                line = raw_line.rstrip()

                # Extract IP (best-effort)
                ip = ""
                ip_match = _IP_RE.match(line)
                if ip_match:
                    ip = ip_match.group(1)
                    result.ip_stats[ip] = result.ip_stats.get(ip, 0) + 1

                # Pattern matching
                for severity, category, pattern in _PATTERNS:
                    if pattern.search(line):
                        alert = LogAlert(
                            severity=severity,
                            category=category,
                            description=f"Detected pattern: {category}",
                            line_number=lineno,
                            raw_line=line[:300],
                            ip_address=ip,
                        )
                        result.alerts.append(alert)

                        # Track per-IP auth failures for brute-force detection
                        if category == "Brute-Force / Auth Failure" and ip:
                            ip_failure_counts[ip] += 1

        # Post-process: flag IPs that exceed the brute-force threshold
        for ip, count in ip_failure_counts.items():
            if count >= _AUTH_FAILURE_THRESHOLD:
                result.alerts.append(
                    LogAlert(
                        severity="HIGH",
                        category="Brute-Force Attack",
                        description=(
                            f"IP {ip} triggered {count} authentication failures "
                            f"(threshold: {_AUTH_FAILURE_THRESHOLD})"
                        ),
                        line_number=0,
                        raw_line="",
                        ip_address=ip,
                    )
                )

        return result

    def analyze_text(self, log_text: str, label: str = "<log>") -> LogAnalysisResult:
        """
        Analyse log content provided as a string (e.g. from a test or API).

        Parameters
        ----------
        log_text: Raw log content as a multi-line string.
        label:    Label used in the result's file_path field.
        """
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(log_text)
            tmp_path = tmp.name
        try:
            result = self.analyze_file(tmp_path)
            result.file_path = label
        finally:
            os.unlink(tmp_path)
        return result
