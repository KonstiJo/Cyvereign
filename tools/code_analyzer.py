"""
tools/code_analyzer.py
======================
Static pattern-based code vulnerability scanner.

This tool scans source code (Python, C, C++, JavaScript, Go) for common
security anti-patterns using regular expressions.  It is intentionally
kept simple so the logic is easy to follow and extend.

For production use you would complement this with AST-based analysis or
dedicated tools like Semgrep / Bandit / CodeQL.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class Vulnerability:
    """Represents a single detected vulnerability."""
    severity: str          # "HIGH", "MEDIUM", or "LOW"
    category: str          # e.g. "SQL Injection"
    description: str       # human-readable explanation
    line_number: int        # 1-based line number in the source file
    line_content: str      # the offending line (stripped)
    cwe: str = ""          # optional CWE identifier, e.g. "CWE-89"


@dataclass
class ScanResult:
    """Aggregated result of scanning one file."""
    file_path: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    def summary(self) -> str:
        if not self.vulnerabilities:
            return f"✅ No vulnerabilities found in {self.file_path}"
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in self.vulnerabilities:
            counts[v.severity] += 1
        return (
            f"⚠️  {self.file_path}: "
            f"{counts['HIGH']} HIGH | {counts['MEDIUM']} MEDIUM | {counts['LOW']} LOW"
        )


# ---------------------------------------------------------------------------
# Vulnerability patterns
# ---------------------------------------------------------------------------
# Each pattern is a tuple: (severity, category, cwe, regex_pattern)

VULNERABILITY_PATTERNS: List[tuple] = [
    # SQL Injection -------------------------------------------------------
    # Detect string concatenation inside execute() calls and f-string queries.
    # Parameterised queries (e.g. %s with a tuple) are intentionally excluded.
    (
        "HIGH", "SQL Injection", "CWE-89",
        r'(execute|cursor\.execute|query)\s*\(\s*["\'][^"\']*["\']?\s*\+|'
        r'execute\s*\(\s*f["\']',
    ),
    # Command Injection ---------------------------------------------------
    (
        "HIGH", "Command Injection", "CWE-78",
        r'(os\.system|subprocess\.call|subprocess\.run|popen)\s*\(\s*[^,\)]*\+',
    ),
    # Hardcoded secrets ---------------------------------------------------
    (
        "HIGH", "Hardcoded Secret", "CWE-798",
        r'(password|passwd|secret|api_key|token)\s*=\s*["\'][^"\']{4,}["\']',
    ),
    # Path traversal ------------------------------------------------------
    (
        "HIGH", "Path Traversal", "CWE-22",
        r'open\s*\(\s*(request\.|input\(|sys\.argv)',
    ),
    # Unsafe deserialization ----------------------------------------------
    (
        "HIGH", "Unsafe Deserialization", "CWE-502",
        r'pickle\.loads?\s*\(|yaml\.load\s*\([^,\)]+\)',
    ),
    # Eval / exec ---------------------------------------------------------
    (
        "HIGH", "Code Injection via eval/exec", "CWE-95",
        r'\beval\s*\(|\bexec\s*\(',
    ),
    # Weak cryptography ---------------------------------------------------
    (
        "MEDIUM", "Weak Cryptography", "CWE-327",
        r'\b(md5|sha1)\s*\(|hashlib\.(md5|sha1)\s*\(',
    ),
    # Insecure random -----------------------------------------------------
    (
        "MEDIUM", "Insecure Randomness", "CWE-338",
        r'\brandom\.(random|randint|choice|seed)\s*\(',
    ),
    # Debug / verbose logging in production ------------------------------
    (
        "LOW", "Debug Code / Information Disclosure", "CWE-215",
        r'\b(print|console\.log|fmt\.Print)\s*\(.*(?:password|token|secret)',
    ),
    # Missing TLS verification --------------------------------------------
    (
        "MEDIUM", "TLS Verification Disabled", "CWE-295",
        r'verify\s*=\s*False|ssl\._create_unverified_context',
    ),
    # Buffer-related C patterns -------------------------------------------
    (
        "HIGH", "Buffer Overflow Risk (C/C++)", "CWE-120",
        r'\b(strcpy|strcat|gets|sprintf|scanf)\s*\(',
    ),
    # Format string -------------------------------------------------------
    (
        "HIGH", "Format String Vulnerability", "CWE-134",
        r'printf\s*\(\s*[a-zA-Z_]\w*\s*\)',
    ),
]

# Human-readable descriptions for each category
_DESCRIPTIONS: dict[str, str] = {
    "SQL Injection": (
        "User input may be concatenated directly into an SQL query. "
        "Use parameterised queries or an ORM instead."
    ),
    "Command Injection": (
        "Shell command is constructed with user-controlled data. "
        "Use subprocess with a list of arguments and avoid shell=True."
    ),
    "Hardcoded Secret": (
        "A secret appears to be hard-coded. "
        "Store secrets in environment variables or a secrets manager."
    ),
    "Path Traversal": (
        "File path derived from user input may allow directory traversal. "
        "Validate and sanitise file paths; use pathlib.Path.resolve()."
    ),
    "Unsafe Deserialization": (
        "Deserialising untrusted data can lead to arbitrary code execution. "
        "Use safe formats like JSON; if using YAML, pass Loader=yaml.SafeLoader."
    ),
    "Code Injection via eval/exec": (
        "eval()/exec() with user-supplied input can execute arbitrary code. "
        "Avoid eval/exec entirely or use ast.literal_eval for safe parsing."
    ),
    "Weak Cryptography": (
        "MD5 and SHA-1 are cryptographically broken. "
        "Use SHA-256 or SHA-3 for hashing; use bcrypt/argon2 for passwords."
    ),
    "Insecure Randomness": (
        "The `random` module is not cryptographically secure. "
        "Use `secrets` module for security-sensitive randomness."
    ),
    "Debug Code / Information Disclosure": (
        "Sensitive data may be leaked through debug output. "
        "Remove or guard debug prints before deploying to production."
    ),
    "TLS Verification Disabled": (
        "Disabling TLS certificate verification exposes the connection to MITM attacks. "
        "Always verify certificates in production code."
    ),
    "Buffer Overflow Risk (C/C++)": (
        "Unsafe string/memory functions with no bounds checking. "
        "Use safer alternatives: strncpy, strncat, fgets, snprintf."
    ),
    "Format String Vulnerability": (
        "Passing a user-controlled string directly as the format argument to printf "
        "can lead to arbitrary memory reads/writes. Use printf(\"%s\", var) instead."
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class CodeAnalyzer:
    """
    Scans source code for common security vulnerabilities.

    Usage:
        analyzer = CodeAnalyzer()
        result = analyzer.scan_file("path/to/app.py")
        print(result.summary())
        for vuln in result.vulnerabilities:
            print(f"  Line {vuln.line_number}: [{vuln.severity}] {vuln.category}")
    """

    def scan_code(self, code: str, file_label: str = "<code>") -> ScanResult:
        """
        Scan a string of source code and return a ScanResult.

        Parameters
        ----------
        code:       The raw source code as a string.
        file_label: A label used in the result (e.g. the file path).
        """
        result = ScanResult(file_path=file_label)
        lines = code.splitlines()

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            for severity, category, cwe, pattern in VULNERABILITY_PATTERNS:
                if re.search(pattern, stripped, re.IGNORECASE):
                    result.vulnerabilities.append(
                        Vulnerability(
                            severity=severity,
                            category=category,
                            description=_DESCRIPTIONS.get(category, ""),
                            line_number=lineno,
                            line_content=stripped,
                            cwe=cwe,
                        )
                    )
        return result

    def scan_file(self, file_path: str) -> ScanResult:
        """
        Read a file from disk and scan it.

        Parameters
        ----------
        file_path: Absolute or relative path to the source file.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        code = path.read_text(encoding="utf-8", errors="ignore")
        return self.scan_code(code, file_label=str(path))

    def scan_directory(self, directory: str, extensions: List[str] | None = None) -> List[ScanResult]:
        """
        Recursively scan all matching source files in a directory.

        Parameters
        ----------
        directory:  Root directory to scan.
        extensions: List of file extensions to include (default: common source files).
        """
        if extensions is None:
            extensions = [".py", ".c", ".cpp", ".h", ".js", ".ts", ".go"]

        root = Path(directory)
        if not root.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        results: List[ScanResult] = []
        for ext in extensions:
            for file_path in root.rglob(f"*{ext}"):
                results.append(self.scan_file(str(file_path)))
        return results
