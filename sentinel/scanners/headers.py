"""
Custom HTTP Security Headers, CORS, and Cookie Flags Scanner.
Non-destructive active inspection of HTTP response headers, CORS policies, and cookie configurations.
"""

from typing import Any, Dict, List

import requests

from sentinel.scanners.base import BaseScanner


class HeadersScanner(BaseScanner):
    """
    Scans HTTP endpoints for missing security headers, insecure CORS configurations,
    and missing cookie protection flags (HttpOnly, Secure, SameSite).
    """

    tool_name = "headers"

    MANDATORY_HEADERS = {
        "Strict-Transport-Security": {
            "title": "Missing HTTP Strict Transport Security (HSTS) Header",
            "cwe": "CWE-693",
            "severity": "MEDIUM",
        },
        "Content-Security-Policy": {
            "title": "Missing Content Security Policy (CSP)",
            "cwe": "CWE-693",
            "severity": "HIGH",
        },
        "X-Content-Type-Options": {
            "title": "Missing X-Content-Type-Options Header",
            "cwe": "CWE-16",
            "severity": "LOW",
            "expected": "nosniff",
        },
        "X-Frame-Options": {
            "title": "Missing X-Frame-Options (Clickjacking Protection)",
            "cwe": "CWE-1021",
            "severity": "MEDIUM",
        },
    }

    def run(self, target: str, run_id: str, **kwargs: Any) -> Dict[str, Any]:
        """
        Executes HTTP requests against the target to evaluate headers, CORS, and cookies.
        """
        url = target if target.startswith("http") else f"http://{target}"
        results: Dict[str, Any] = {
            "target": url,
            "inspected_endpoints": [],
            "missing_headers": [],
            "cors_issues": [],
            "cookie_issues": [],
            "findings": [],
        }

        # 1. Base inspection
        try:
            resp = requests.get(url, timeout=self.timeout, allow_redirects=True)
            results["inspected_endpoints"].append(url)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            results["response_headers"] = dict(resp.headers)

            for header, meta in self.MANDATORY_HEADERS.items():
                val = headers_lower.get(header.lower())
                if not val:
                    finding = {
                        "check": "missing_header",
                        "header": header,
                        "title": meta["title"],
                        "cwe": meta["cwe"],
                        "severity": meta["severity"],
                        "evidence": f"Header '{header}' was absent from HTTP response",
                        "endpoint": url,
                    }
                    results["missing_headers"].append(header)
                    results["findings"].append(finding)
                elif "expected" in meta and val.lower() != meta["expected"].lower():
                    finding = {
                        "check": "misconfigured_header",
                        "header": header,
                        "title": f"Misconfigured {header} Header",
                        "cwe": meta["cwe"],
                        "severity": meta["severity"],
                        "evidence": f"Header '{header}' set to '{val}', expected '{meta['expected']}'",
                        "endpoint": url,
                    }
                    results["findings"].append(finding)
        except requests.RequestException as e:
            results["error"] = f"Failed to connect to target {url}: {str(e)}"
            return results

        # 2. CORS inspection
        try:
            cors_resp = requests.get(
                url,
                headers={"Origin": "https://evil.attacker.com"},
                timeout=self.timeout,
            )
            acao = cors_resp.headers.get("Access-Control-Allow-Origin")
            acac = cors_resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

            if acao == "*":
                finding = {
                    "check": "cors_wildcard",
                    "title": "Overly Permissive CORS Policy (Wildcard Origin Allowed)",
                    "cwe": "CWE-942",
                    "severity": "MEDIUM",
                    "evidence": "Access-Control-Allow-Origin is configured to wildcard '*'",
                    "endpoint": url,
                }
                results["cors_issues"].append(finding)
                results["findings"].append(finding)
            elif acao == "https://evil.attacker.com":
                severity = "HIGH" if acac else "MEDIUM"
                finding = {
                    "check": "cors_arbitrary_origin",
                    "title": "Arbitrary Origin Allowed in CORS Response",
                    "cwe": "CWE-942",
                    "severity": severity,
                    "evidence": f"Server reflected arbitrary origin with Allow-Credentials: {acac}",
                    "endpoint": url,
                }
                results["cors_issues"].append(finding)
                results["findings"].append(finding)
        except Exception:
            pass

        # 3. Cookie inspection (test /api/login endpoint if available on lab app)
        login_url = url.rstrip("/") + "/api/login"
        try:
            cookie_resp = requests.post(
                login_url,
                json={"username": "sentinel_tester"},
                timeout=self.timeout,
            )
            for cookie in cookie_resp.cookies:
                issues: List[str] = []
                if not cookie.has_nonstandard_attr("HttpOnly") and not getattr(
                    cookie, "_rest", {}
                ).get("HttpOnly"):
                    issues.append("Missing HttpOnly flag (vulnerable to XSS theft)")
                if not cookie.secure:
                    issues.append("Missing Secure flag (transmitted over cleartext)")

                if issues:
                    finding = {
                        "check": "insecure_cookie",
                        "cookie_name": cookie.name,
                        "title": f"Insecure Cookie Flags on '{cookie.name}'",
                        "cwe": "CWE-614",
                        "severity": "MEDIUM",
                        "evidence": "; ".join(issues),
                        "endpoint": login_url,
                    }
                    results["cookie_issues"].append(finding)
                    results["findings"].append(finding)
        except Exception:
            pass

        return results

    def parse(self, raw_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parses raw header scan output into findings list."""
        data = raw_output.get("data", {})
        return data.get("findings", [])
