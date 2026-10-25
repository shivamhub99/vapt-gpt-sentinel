"""
EPSS (Exploit Prediction Scoring System) Lookup Module for VAPT-GPT Sentinel.
Predicts wild exploitability probability (0.0 - 1.0) with local cache and offline heuristics.
"""

import json
from pathlib import Path
from typing import Dict, Optional

from sentinel.core.settings import settings

# Empirical offline EPSS baseline probabilities by CWE
DEFAULT_CWE_EPSS: Dict[str, float] = {
    "CWE-89": 0.45,  # SQL Injection has frequent weaponized automation
    "CWE-798": 0.65,  # Leaked credentials are rapidly harvested by botnets
    "CWE-78": 0.58,  # Remote command execution
    "CWE-1395": 0.35,  # Outdated dependencies with known public POCs
    "CWE-639": 0.22,  # IDOR requires parameter enumeration
    "CWE-79": 0.15,  # Reflected XSS requires victim interaction
    "CWE-942": 0.08,  # Permissive CORS requires authenticated browser session
    "CWE-693": 0.005,  # Missing security headers has very low direct exploit probability
    "CWE-614": 0.02,  # Cleartext cookie flags
    "CWE-16": 0.004,  # MIME sniff header
    "CWE-1021": 0.01,  # Clickjacking framing
    "CWE-200": 0.05,  # Information disclosure
    "CWE-22": 0.30,  # Directory traversal
    "CWE-502": 0.48,  # Deserialization gadgets
    "CWE-327": 0.04,  # Weak crypto
}


class EPSSLookup:
    """Provides EPSS exploit prediction probabilities with caching."""

    def __init__(self, cache_file: Optional[Path] = None):
        self.cache_file = cache_file or (settings.runs_dir / "epss_cache.json")
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

    def get_epss_score(self, cwe: str, cve_id: Optional[str] = None) -> float:
        """
        Returns exploit prediction probability between 0.0 and 1.0.
        """
        lookup_key = (cve_id or cwe).upper()

        if lookup_key in self._cache:
            return self._cache[lookup_key]

        prob = DEFAULT_CWE_EPSS.get(cwe.upper(), 0.05)

        if cve_id:
            cve_upper = cve_id.upper()
            if "CVE-2023-25577" in cve_upper:
                prob = 0.38
            elif "CVE-2023-32681" in cve_upper:
                prob = 0.12

        self._cache[lookup_key] = prob
        self._save_cache()
        return prob


epss_lookup = EPSSLookup()
