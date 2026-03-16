"""
tests/test_code_analyzer.py
===========================
Unit tests for tools/code_analyzer.py.

These tests run without Ollama, network access, or any external services.
"""

import sys
import os

# Add project root to path so imports work from the tests/ directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from tools.code_analyzer import CodeAnalyzer, ScanResult, Vulnerability


@pytest.fixture
def analyzer():
    return CodeAnalyzer()


class TestCodeAnalyzer:
    # ------------------------------------------------------------------
    # SQL Injection
    # ------------------------------------------------------------------

    def test_detects_sql_injection(self, analyzer):
        code = "cursor.execute('SELECT * FROM users WHERE id=' + user_id)"
        result = analyzer.scan_code(code)
        categories = [v.category for v in result.vulnerabilities]
        assert "SQL Injection" in categories

    def test_no_sql_injection_in_safe_code(self, analyzer):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        result = analyzer.scan_code(code)
        categories = [v.category for v in result.vulnerabilities]
        assert "SQL Injection" not in categories

    # ------------------------------------------------------------------
    # Command Injection
    # ------------------------------------------------------------------

    def test_detects_command_injection(self, analyzer):
        code = "os.system('ls ' + user_input)"
        result = analyzer.scan_code(code)
        categories = [v.category for v in result.vulnerabilities]
        assert "Command Injection" in categories

    # ------------------------------------------------------------------
    # Hardcoded Secret
    # ------------------------------------------------------------------

    def test_detects_hardcoded_password(self, analyzer):
        code = 'password = "SuperSecret123"'
        result = analyzer.scan_code(code)
        categories = [v.category for v in result.vulnerabilities]
        assert "Hardcoded Secret" in categories

    def test_detects_hardcoded_api_key(self, analyzer):
        code = 'api_key = "sk-abcdef1234567890"'
        result = analyzer.scan_code(code)
        categories = [v.category for v in result.vulnerabilities]
        assert "Hardcoded Secret" in categories

    # ------------------------------------------------------------------
    # Unsafe Deserialization
    # ------------------------------------------------------------------

    def test_detects_pickle(self, analyzer):
        code = "data = pickle.loads(user_bytes)"
        result = analyzer.scan_code(code)
        categories = [v.category for v in result.vulnerabilities]
        assert "Unsafe Deserialization" in categories

    # ------------------------------------------------------------------
    # Eval / Exec
    # ------------------------------------------------------------------

    def test_detects_eval(self, analyzer):
        code = "result = eval(user_expression)"
        result = analyzer.scan_code(code)
        categories = [v.category for v in result.vulnerabilities]
        assert "Code Injection via eval/exec" in categories

    def test_detects_exec(self, analyzer):
        code = "exec(user_code)"
        result = analyzer.scan_code(code)
        categories = [v.category for v in result.vulnerabilities]
        assert "Code Injection via eval/exec" in categories

    # ------------------------------------------------------------------
    # Weak Cryptography
    # ------------------------------------------------------------------

    def test_detects_md5(self, analyzer):
        code = "digest = hashlib.md5(data).hexdigest()"
        result = analyzer.scan_code(code)
        categories = [v.category for v in result.vulnerabilities]
        assert "Weak Cryptography" in categories

    # ------------------------------------------------------------------
    # TLS Verification
    # ------------------------------------------------------------------

    def test_detects_tls_disabled(self, analyzer):
        code = "requests.get(url, verify=False)"
        result = analyzer.scan_code(code)
        categories = [v.category for v in result.vulnerabilities]
        assert "TLS Verification Disabled" in categories

    # ------------------------------------------------------------------
    # C buffer functions
    # ------------------------------------------------------------------

    def test_detects_strcpy(self, analyzer):
        code = "strcpy(dest, src);"
        result = analyzer.scan_code(code)
        categories = [v.category for v in result.vulnerabilities]
        assert "Buffer Overflow Risk (C/C++)" in categories

    # ------------------------------------------------------------------
    # Clean code
    # ------------------------------------------------------------------

    def test_clean_code_no_vulnerabilities(self, analyzer):
        code = (
            "import hashlib\n"
            "def hash_password(pwd: str) -> str:\n"
            "    return hashlib.sha256(pwd.encode()).hexdigest()\n"
        )
        result = analyzer.scan_code(code)
        # SHA-256 is safe – no weak crypto alert expected
        weak_crypto = [v for v in result.vulnerabilities if v.category == "Weak Cryptography"]
        assert len(weak_crypto) == 0

    # ------------------------------------------------------------------
    # ScanResult helpers
    # ------------------------------------------------------------------

    def test_summary_no_vulns(self, analyzer):
        result = ScanResult(file_path="test.py")
        assert "No vulnerabilities" in result.summary()

    def test_summary_with_vulns(self, analyzer):
        result = ScanResult(
            file_path="test.py",
            vulnerabilities=[
                Vulnerability("HIGH", "SQL Injection", "desc", 1, "line", "CWE-89")
            ],
        )
        summary = result.summary()
        assert "1 HIGH" in summary

    # ------------------------------------------------------------------
    # Line numbers
    # ------------------------------------------------------------------

    def test_correct_line_number(self, analyzer):
        code = "safe_line = 1\nresult = eval(user_input)\nanother_safe = 3"
        result = analyzer.scan_code(code)
        eval_vulns = [v for v in result.vulnerabilities if v.category == "Code Injection via eval/exec"]
        assert eval_vulns
        assert eval_vulns[0].line_number == 2

    # ------------------------------------------------------------------
    # File scanning
    # ------------------------------------------------------------------

    def test_scan_file_not_found(self, analyzer):
        with pytest.raises(FileNotFoundError):
            analyzer.scan_file("/nonexistent/path/file.py")

    def test_scan_directory_not_found(self, analyzer):
        with pytest.raises(NotADirectoryError):
            analyzer.scan_directory("/nonexistent/directory")
