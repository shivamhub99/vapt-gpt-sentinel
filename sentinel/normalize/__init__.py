"""
Finding Normalization Package for VAPT-GPT Sentinel.
"""

from sentinel.normalize.cwe_map import get_owasp_category, normalize_cwe
from sentinel.normalize.dedupe import deduplicate_findings
from sentinel.normalize.normalizer import Normalizer, normalizer

__all__ = [
    "Normalizer",
    "normalizer",
    "normalize_cwe",
    "get_owasp_category",
    "deduplicate_findings",
]
