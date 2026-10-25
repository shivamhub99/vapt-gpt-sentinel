"""
CVSS Scoring and Threat Intelligence Module for VAPT-GPT Sentinel.
Provides CVSS v3.1 base score lookup with local persistent cache and offline heuristics.
"""

import json
from pathlib import Path
from typing import Dict, Optional

from sentinel.core.settings import settings

# Canonical CVSS v3.1 base scores for standard CWEs
DEFAULT_CWE_CVSS: Dict[str, float] = {
    "CWE-89": 8.8,  # SQL Injection (High/Critical)
    "CWE-79": 6.1,  # Reflected XSS (Medium)
    "CWE-78": 9.8,  # OS Command Injection (Critical)
    "CWE-798": 9.8,  # Hardcoded Credentials (Critical)
    "CWE-639": 7.5,  # Insecure Direct Object Reference (High)
    "CWE-1395": 7.5,  # Dependency with Known Vulnerability (High)
    "CWE-693": 5.3,  # Missing Security Headers (Medium)
    "CWE-942": 6.5,  # Permissive CORS (Medium)
    "CWE-614": 4.3,  # Insecure Cookie without Secure flag (Medium)
    "CWE-1021": 4.3,  # Missing X-Frame-Options (Medium)
    "CWE-16": 3.7,  # Missing X-Content-Type-Options (Low)
    "CWE-200": 5.3,  # Information Exposure (Medium)
    "CWE-22": 7.5,  # Path Traversal (High)
    "CWE-502": 9.8,  # Insecure Deserialization (Critical)
    "CWE-327": 7.5,  # Broken/Weak Cryptography (High)
}


class CVSSLookup:
    """Manages CVSS scores with persistent caching and heuristic fallback."""

    def __init__(self, cache_file: Optional[Path] = None):
        self.cache_file = cache_file or (settings.runs_dir / "cvss_cache.json")
        self._cache: Dict[str, float] = self._load_cache()

    def _load_cache(self) -> Dict[str, float]:
        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_cache(self) -> None:
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2)
        except Exception:
            pass

    def get_cvss_score(self, cwe: str, cve_id: Optional[str] = None) -> float:
        """
        Retrieves CVSS base score (0.0 - 10.0) from cache, CVE, or CWE default.
        """
        lookup_key = (cve_id or cwe).upper()

        if lookup_key in self._cache:
            return self._cache[lookup_key]

        # Standard known CWE fallback
        score = DEFAULT_CWE_CVSS.get(cwe.upper(), 5.0)

        # High severity CVE specific adjustments
        if cve_id:
            cve_upper = cve_id.upper()
            if "CVE-2023-25577" in cve_upper:
                score = 7.5
            elif "CVE-2023-32681" in cve_upper:
                score = 6.5

        self._cache[lookup_key] = score
        self._save_cache()
        return score


cvss_lookup = CVSSLookup()
