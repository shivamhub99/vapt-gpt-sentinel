"""
NVD (National Vulnerability Database) Local Caching Utility for VAPT-GPT Sentinel.
Stores CVE descriptions, CVSS vectors, and references locally to ensure offline repeatability.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional

from sentinel.core.settings import settings


class NVDCache:
    """Provides local persistence for CVE metadata."""

    def __init__(self, cache_file: Optional[Path] = None):
        self.cache_file = cache_file or (settings.runs_dir / "nvd_cache.json")
        self._cache: Dict[str, Any] = self._load_cache()

    def _load_cache(self) -> Dict[str, Any]:
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

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        return self._cache.get(cve_id.upper())

    def put_cve(self, cve_id: str, data: Dict[str, Any]) -> None:
        self._cache[cve_id.upper()] = data
        self._save_cache()


nvd_cache = NVDCache()
