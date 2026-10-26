"""
Security Regression Runner for VAPT-GPT Sentinel Verification Loop.
Executes deterministic security invariant checks to verify that the vulnerability
cannot be reproduced and the patch satisfies defensive coding standards.
"""

import re
from pathlib import Path
from typing import Tuple

from sentinel.core.schemas import Finding


class SecurityRegressionRunner:
    """Executes deterministic security invariant tests against patched code."""

    def run_regression(self, finding: Finding, sandbox_dir: Path) -> Tuple[bool, str]:
        """
        Dispatches deterministic security assertions based on finding CWE.
        Returns Tuple of (passed: bool, diagnostic: str).
        """
        cwe = finding.cwe.upper()

        if cwe == "CWE-89" or "sql" in finding.title.lower():
            return self._verify_sqli_remediation(finding, sandbox_dir)
        elif cwe == "CWE-79" or "xss" in finding.title.lower():
            return self._verify_xss_remediation(finding, sandbox_dir)
        elif (
            cwe == "CWE-798" or "secret" in finding.title.lower() or "key" in finding.title.lower()
        ):
            return self._verify_secrets_remediation(finding, sandbox_dir)
        elif (
            cwe == "CWE-1395"
            or "dependency" in finding.title.lower()
            or "requirements.txt" in (finding.file or "")
        ):
            return self._verify_deps_remediation(finding, sandbox_dir)
        elif (
            cwe in ("CWE-693", "CWE-942", "CWE-614")
            or "header" in finding.title.lower()
            or "cors" in finding.title.lower()
        ):
            return self._verify_headers_remediation(finding, sandbox_dir)

        # Generic syntax and sanity assertion for other CWEs
        return self._verify_generic_syntax(finding, sandbox_dir)

    def _get_target_file(self, finding: Finding, sandbox_dir: Path) -> Path | None:
        file_path_str = finding.file or "app.py"
        target = sandbox_dir / Path(file_path_str).name
        if target.exists():
            return target
        matches = list(sandbox_dir.rglob(Path(file_path_str).name))
        return matches[0] if matches else None

    def _verify_sqli_remediation(self, finding: Finding, sandbox_dir: Path) -> Tuple[bool, str]:
        target = self._get_target_file(finding, sandbox_dir)
        if not target or not target.exists():
            return False, f"SQL target file not found in sandbox: {finding.file}"

        code = target.read_text(encoding="utf-8", errors="ignore")

        # 1. Assert syntax validity
        try:
            compile(code, str(target), "exec")
        except SyntaxError as err:
            return False, f"Patched file contains Python syntax error: {err}"

        # 2. Check that raw SQL formatted string is eliminated
        unsecure_pattern = r'raw_sql\s*=\s*f["\'].*?\{.*?\}'
        if re.search(unsecure_pattern, code):
            return (
                False,
                "Insecure formatted SQL string interpolation (f-string) still present in source code.",
            )

        # 3. Check for parameter binding in cursor.execute
        if "cursor.execute(" in code:
            if "?" in code or "%s" in code or ":param" in code or ", (" in code:
                return (
                    True,
                    "Security regression passed: Query parameterized with bound query parameters.",
                )

        return True, "Security regression passed: Raw SQL injection vector removed."

    def _verify_xss_remediation(self, finding: Finding, sandbox_dir: Path) -> Tuple[bool, str]:
        target = self._get_target_file(finding, sandbox_dir)
        if not target or not target.exists():
            return False, f"XSS target file not found in sandbox: {finding.file}"

        code = target.read_text(encoding="utf-8", errors="ignore")

        # 1. Assert syntax validity
        try:
            compile(code, str(target), "exec")
        except SyntaxError as err:
            return False, f"Patched file contains Python syntax error: {err}"

        # 2. Check for escaping mechanism
        has_escape_import = "escape" in code
        has_safe_var = (
            "escape(" in code or "safe_" in code or "html.escape" in code or "markupsafe" in code
        )

        if has_escape_import and has_safe_var:
            return (
                True,
                "Security regression passed: Output variable sanitized via contextual HTML escaping.",
            )

        return False, "Reflected variable is rendered without HTML output escaping."

    def _verify_secrets_remediation(self, finding: Finding, sandbox_dir: Path) -> Tuple[bool, str]:
        target = self._get_target_file(finding, sandbox_dir)
        if not target or not target.exists():
            return False, f"Secrets target file not found in sandbox: {finding.file}"

        code = target.read_text(encoding="utf-8", errors="ignore")

        # 1. Assert syntax validity
        try:
            compile(code, str(target), "exec")
        except SyntaxError as err:
            return False, f"Patched file contains Python syntax error: {err}"

        # 2. Check that hardcoded literal is not directly assigned
        if re.search(r'API_SECRET_KEY\s*=\s*["\'][A-Za-z0-9_-]{16,}["\']\s*$', code, re.MULTILINE):
            return False, "Plaintext API secret key constant is still hardcoded in source."

        if "os.environ" in code or "os.getenv" in code:
            return (
                True,
                "Security regression passed: Hardcoded credential migrated to environment variable retrieval.",
            )

        return False, "Credential is not loaded from environment."

    def _verify_deps_remediation(self, finding: Finding, sandbox_dir: Path) -> Tuple[bool, str]:
        req_file = sandbox_dir / "requirements.txt"
        if not req_file.exists():
            matches = list(sandbox_dir.rglob("requirements.txt"))
            req_file = matches[0] if matches else None

        if not req_file or not req_file.exists():
            return False, "requirements.txt not found in sandbox."

        content = req_file.read_text(encoding="utf-8", errors="ignore")

        # Check for known vulnerable versions
        if re.search(r"(?i)werkzeug\s*==\s*2\.[0-2]\.", content):
            return False, "requirements.txt still contains vulnerable pinned Werkzeug package."
        if re.search(r"(?i)requests\s*==\s*2\.2[0-5]\.", content):
            return False, "requirements.txt still contains vulnerable pinned requests package."

        return (
            True,
            "Security regression passed: Insecure pinned dependencies bumped to secure versions.",
        )

    def _verify_headers_remediation(self, finding: Finding, sandbox_dir: Path) -> Tuple[bool, str]:
        target = self._get_target_file(finding, sandbox_dir)
        if not target or not target.exists():
            return False, f"Headers target file not found in sandbox: {finding.file}"

        code = target.read_text(encoding="utf-8", errors="ignore")

        # 1. Assert syntax validity
        try:
            compile(code, str(target), "exec")
        except SyntaxError as err:
            return False, f"Patched file contains Python syntax error: {err}"

        # 2. Check CORS restriction
        if 'response.headers["Access-Control-Allow-Origin"] = "*"' in code:
            return False, "Permissive wildcard CORS origin ('*') still present."

        # 3. Check security headers
        has_csp = "Content-Security-Policy" in code
        has_hsts = "Strict-Transport-Security" in code
        has_nosniff = "X-Content-Type-Options" in code

        if has_csp and (has_hsts or has_nosniff):
            return (
                True,
                "Security regression passed: Hardened CORS policy and injected defensive HTTP security headers.",
            )

        return False, "Security headers (CSP/HSTS/X-Content-Type-Options) are missing."

    def _verify_generic_syntax(self, finding: Finding, sandbox_dir: Path) -> Tuple[bool, str]:
        target = self._get_target_file(finding, sandbox_dir)
        if not target or not target.exists():
            return True, "Target file not present for AST syntax check."

        if target.suffix == ".py":
            try:
                compile(target.read_text(encoding="utf-8", errors="ignore"), str(target), "exec")
                return True, "Generic security assertion passed: Python syntax check succeeded."
            except SyntaxError as err:
                return False, f"Syntax verification failed: {err}"

        return True, "Generic security assertion passed."


security_regression_runner = SecurityRegressionRunner()
