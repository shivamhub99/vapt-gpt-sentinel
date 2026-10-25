"""
CWE and OWASP Top 10 Classification and Normalization Engine.
Translates heterogeneous scanner rule IDs into canonical CWE numbers and OWASP Top 10 (2021) categories.
"""

import re
from typing import Dict, Optional, Tuple

# Mapping of canonical CWE to OWASP Top 10 2021 categories
CWE_TO_OWASP: Dict[str, str] = {
    # A01: Broken Access Control
    "CWE-639": "A01:2021-Broken Access Control",
    "CWE-284": "A01:2021-Broken Access Control",
    "CWE-285": "A01:2021-Broken Access Control",
    "CWE-22": "A01:2021-Broken Access Control",
    "CWE-862": "A01:2021-Broken Access Control",
    # A02: Cryptographic Failures
    "CWE-327": "A02:2021-Cryptographic Failures",
    "CWE-328": "A02:2021-Cryptographic Failures",
    "CWE-330": "A02:2021-Cryptographic Failures",
    "CWE-312": "A02:2021-Cryptographic Failures",
    # A03: Injection
    "CWE-89": "A03:2021-Injection",
    "CWE-79": "A03:2021-Injection",
    "CWE-78": "A03:2021-Injection",
    "CWE-94": "A03:2021-Injection",
    "CWE-91": "A03:2021-Injection",
    # A05: Security Misconfiguration
    "CWE-16": "A05:2021-Security Misconfiguration",
    "CWE-693": "A05:2021-Security Misconfiguration",
    "CWE-1021": "A05:2021-Security Misconfiguration",
    "CWE-942": "A05:2021-Security Misconfiguration",
    "CWE-614": "A05:2021-Security Misconfiguration",
    "CWE-1004": "A05:2021-Security Misconfiguration",
    "CWE-1275": "A05:2021-Security Misconfiguration",
    "CWE-200": "A05:2021-Security Misconfiguration",
    # A06: Vulnerable and Outdated Components
    "CWE-1395": "A06:2021-Vulnerable and Outdated Components",
    "CWE-1104": "A06:2021-Vulnerable and Outdated Components",
    "CWE-937": "A06:2021-Vulnerable and Outdated Components",
    # A07: Identification and Authentication Failures
    "CWE-798": "A07:2021-Identification and Authentication Failures",
    "CWE-287": "A07:2021-Identification and Authentication Failures",
    "CWE-384": "A07:2021-Identification and Authentication Failures",
    # A08: Software and Data Integrity Failures
    "CWE-502": "A08:2021-Software and Data Integrity Failures",
    "CWE-494": "A08:2021-Software and Data Integrity Failures",
    # A10: Server-Side Request Forgery
    "CWE-918": "A10:2021-Server-Side Request Forgery (SSRF)",
}

# Explicit rule ID mappings for tools
TOOL_RULE_MAP: Dict[Tuple[str, str], str] = {
    # Bandit mappings
    ("bandit", "B608"): "CWE-89",
    ("bandit", "B105"): "CWE-798",
    ("bandit", "B106"): "CWE-798",
    ("bandit", "B107"): "CWE-798",
    ("bandit", "B104"): "CWE-200",
    ("bandit", "B301"): "CWE-502",
    ("bandit", "B601"): "CWE-78",
    ("bandit", "B602"): "CWE-78",
    ("bandit", "B303"): "CWE-327",
    # ZAP mappings
    ("zap", "40018"): "CWE-89",
    ("zap", "40012"): "CWE-79",
    ("zap", "10020"): "CWE-1021",
    ("zap", "10021"): "CWE-16",
    ("zap", "10038"): "CWE-693",
    ("zap", "10010"): "CWE-614",
    ("zap", "10011"): "CWE-1004",
    ("zap", "10054"): "CWE-1275",
    # Headers scanner mappings
    ("headers", "missing_header"): "CWE-693",
    ("headers", "cors_wildcard"): "CWE-942",
    ("headers", "cors_arbitrary_origin"): "CWE-942",
    ("headers", "insecure_cookie"): "CWE-614",
    # Gitleaks mappings
    ("gitleaks", "sentinel-secret-rule"): "CWE-798",
    ("gitleaks", "generic-api-key"): "CWE-798",
    ("gitleaks", "aws-access-token"): "CWE-798",
    # Supply chain scanners
    ("pip_audit", "dependency"): "CWE-1395",
    ("trivy", "vulnerability"): "CWE-1395",
}


def normalize_cwe(tool: str, raw_rule: str, raw_cwe: Optional[str] = None) -> str:
    """
    Normalizes any rule identifier or raw CWE string to canonical 'CWE-XXX' format.
    """
    # 1. If explicit tool rule mapping exists
    rule_key = (tool.lower(), raw_rule.strip())
    if rule_key in TOOL_RULE_MAP:
        return TOOL_RULE_MAP[rule_key]

    # 2. Extract from raw_cwe string if given (e.g. 'CWE-89: SQL Injection' or 'cwe-89' or '89')
    if raw_cwe:
        match = re.search(r"CWE-(\d+)", str(raw_cwe), re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)}"
        if str(raw_cwe).isdigit():
            return f"CWE-{raw_cwe}"

    # 3. Check rule string text for keywords
    lower_rule = raw_rule.lower()
    if "sql" in lower_rule and ("inject" in lower_rule or "sqli" in lower_rule):
        return "CWE-89"
    if "xss" in lower_rule or "cross-site-scripting" in lower_rule:
        return "CWE-79"
    if "secret" in lower_rule or "password" in lower_rule or "key" in lower_rule:
        return "CWE-798"
    if "idor" in lower_rule or "direct-object" in lower_rule or "access-control" in lower_rule:
        return "CWE-639"
    if "traversal" in lower_rule or "path" in lower_rule and "travers" in lower_rule:
        return "CWE-22"
    if "cors" in lower_rule:
        return "CWE-942"
    if "hsts" in lower_rule or "csp" in lower_rule or "header" in lower_rule:
        return "CWE-693"
    if "cve-" in lower_rule:
        return "CWE-1395"

    return "CWE-Unknown"


def get_owasp_category(cwe: str) -> str:
    """Returns the OWASP Top 10 (2021) category for a given canonical CWE."""
    return CWE_TO_OWASP.get(cwe, "A05:2021-Security Misconfiguration")
