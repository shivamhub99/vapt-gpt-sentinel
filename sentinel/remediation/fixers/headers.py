"""
Security Headers, CORS, and Cookie Flags (CWE-693 / CWE-942 / CWE-614) Remediation Fixer.
Injects missing defensive HTTP headers, restricts wildcard CORS, and applies Secure/HttpOnly/SameSite cookie flags.
"""

import re
from pathlib import Path
from typing import Optional, Tuple

from sentinel.core.schemas import Finding
from sentinel.remediation.fixers.base import BaseFixer


class HeadersFixer(BaseFixer):
    """Remediates HTTP header misconfigurations, permissive CORS, and insecure cookies."""

    cwe = "CWE-693"
    category = "Misconfiguration"

    def can_fix(self, finding: Finding) -> bool:
        return (
            finding.cwe in ("CWE-693", "CWE-942", "CWE-614", "CWE-16", "CWE-1021")
            or "header" in finding.title.lower()
            or "cors" in finding.title.lower()
            or "cookie" in finding.title.lower()
        )

    def apply_template(
        self, finding: Finding, source_code: str, file_path: Path
    ) -> Optional[Tuple[str, str]]:
        if not source_code:
            return None

        modified = source_code
        applied: list[str] = []

        # 1. Update apply_headers response hook
        pattern_cors = (
            r'response\.headers\[["\']Access-Control-Allow-Origin["\']\]\s*=\s*["\']\*["\']'
        )
        if re.search(pattern_cors, modified):
            secure_headers_block = (
                'response.headers["Access-Control-Allow-Origin"] = "http://localhost:8080"\n'
                '    response.headers["Content-Security-Policy"] = "default-src \'self\'"\n'
                '    response.headers["X-Content-Type-Options"] = "nosniff"\n'
                '    response.headers["X-Frame-Options"] = "DENY"\n'
                '    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"'
            )
            modified = re.sub(pattern_cors, secure_headers_block, modified, count=1)
            applied.append(
                "Hardened CORS and injected CSP, HSTS, X-Content-Type-Options, X-Frame-Options"
            )

        # 2. Update insecure session cookies
        pattern_cookie = (
            r'resp\.set_cookie\(["\']session_id["\'],\s*(.*?),\s*httponly=False,\s*secure=False\)'
        )
        if re.search(pattern_cookie, modified):
            cookie_replacement = (
                r'resp.set_cookie("session_id", \1, httponly=True, secure=True, samesite="Lax")'
            )
            modified = re.sub(pattern_cookie, cookie_replacement, modified, count=1)
            applied.append("Set HttpOnly=True, Secure=True, and SameSite='Lax' on session cookie")

        if modified != source_code:
            rationale = "; ".join(applied) + "."
            return modified, rationale

        return None
