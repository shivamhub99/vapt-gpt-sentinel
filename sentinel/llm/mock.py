"""
Mock LLM Provider for VAPT-GPT Sentinel.
Returns deterministic, structured explanations and canned unified diff patches
so the entire pipeline, test suite, and evaluation harness can run 100% offline.
"""

from typing import Any, Dict, Optional

from sentinel.llm.base import LLMProvider


class MockProvider(LLMProvider):
    """Provides deterministic offline LLM responses for explanations and patches."""

    provider_name: str = "mock"

    def explain_risk(self, finding_title: str, cwe: str, context_factors: Dict[str, Any]) -> str:
        sensitivity = context_factors.get("data_sensitivity", "public")
        facing = "internet-facing" if context_factors.get("internet_facing") else "internal"
        auth = (
            "requires authentication" if context_factors.get("auth_required") else "unauthenticated"
        )

        return (
            f"Contextual Threat Analysis: {finding_title} ({cwe}) is situated in an {facing}, "
            f"{auth} component processing {sensitivity} data. Because this endpoint directly connects "
            f"to critical downstream services, exploitation allows an adversary to compromise the "
            f"integrity and confidentiality of the asset without prerequisite credentials."
        )

    def generate_patch(
        self,
        cwe: str,
        finding_title: str,
        file_path: str,
        source_code: str,
        evidence: str,
        failure_feedback: Optional[str] = None,
    ) -> Dict[str, str]:
        """Returns canned unified diff patches tailored to standard CWEs in sentinel-lab-app."""
        cwe_clean = cwe.upper()

        if cwe_clean == "CWE-89":  # SQL Injection
            diff = (
                "--- a/app.py\n"
                "+++ b/app.py\n"
                "@@ -155,5 +155,5 @@\n"
                "-    raw_sql = f\"SELECT id, name, description, price FROM products WHERE name LIKE '%{query}%'\"\n"
                "-    cursor.execute(raw_sql)\n"
                '+    query_param = f"%{query}%"\n'
                '+    cursor.execute("SELECT id, name, description, price FROM products WHERE name LIKE ?", (query_param,))\n'
            )
            rationale = "Replaced unsafe raw string formatting in SQL query with parameterized query binding."
            return {"diff": diff, "rationale": rationale}

        if cwe_clean == "CWE-79":  # XSS
            diff = (
                "--- a/app.py\n"
                "+++ b/app.py\n"
                "@@ -170,3 +170,4 @@\n"
                "+    from markupsafe import escape\n"
                "-    html_content = f\"<html><body><div id='greeting'>Welcome back, {name}!</div></body></html>\"\n"
                "+    safe_name = escape(name)\n"
                "+    html_content = f\"<html><body><div id='greeting'>Welcome back, {safe_name}!</div></body></html>\"\n"
            )
            rationale = "Applied contextual HTML escaping via markupsafe.escape() to neutralize reflected scripts."
            return {"diff": diff, "rationale": rationale}

        if cwe_clean == "CWE-798":  # Hardcoded Secret
            diff = (
                "--- a/app.py\n"
                "+++ b/app.py\n"
                "@@ -25,2 +25,2 @@\n"
                '-API_SECRET_KEY = "SENTINEL-SECRET-KEY-9988-PROD-DO-NOT-LEAK"\n'
                '+API_SECRET_KEY = os.environ.get("API_SECRET_KEY", "SENTINEL-SECRET-KEY-9988-PROD-DO-NOT-LEAK")\n'
            )
            rationale = "Moved hardcoded credential to environment variable with safe fallback."
            return {"diff": diff, "rationale": rationale}

        if cwe_clean == "CWE-1395":  # Vulnerable dependencies
            diff = (
                "--- a/requirements.txt\n"
                "+++ b/requirements.txt\n"
                "@@ -2,2 +2,2 @@\n"
                "-Werkzeug==2.2.2\n"
                "-requests==2.25.1\n"
                "+Werkzeug>=2.3.8\n"
                "+requests>=2.31.0\n"
            )
            rationale = "Bumped vulnerable pinned dependencies to secure patched releases."
            return {"diff": diff, "rationale": rationale}

        if cwe_clean in ("CWE-693", "CWE-942", "CWE-614"):  # Security Headers & CORS
            diff = (
                "--- a/app.py\n"
                "+++ b/app.py\n"
                "@@ -115,4 +115,7 @@\n"
                '-    response.headers["Access-Control-Allow-Origin"] = "*"\n'
                '+    response.headers["Access-Control-Allow-Origin"] = "http://localhost:8080"\n'
                '+    response.headers["Content-Security-Policy"] = "default-src \'self\'"\n'
                '+    response.headers["X-Content-Type-Options"] = "nosniff"\n'
                '+    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"\n'
            )
            rationale = "Injected mandatory security headers (CSP, HSTS, X-Content-Type-Options) and restricted CORS origin."
            return {"diff": diff, "rationale": rationale}

        # Generic safe patch fallback
        return {
            "diff": f"--- a/{file_path}\n+++ b/{file_path}\n@@ -1,1 +1,1 @@\n# Safe patch applied\n",
            "rationale": f"Generic defensive mitigation applied for {cwe}.",
        }
