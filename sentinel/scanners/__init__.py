"""
Scanner Wrappers for VAPT-GPT Sentinel.
Provides safe orchestration of AST, SAST, DAST baseline, dependency, and network scanners.
"""

from typing import Dict, Type

from sentinel.scanners.bandit import BanditScanner
from sentinel.scanners.base import BaseScanner
from sentinel.scanners.gitleaks import GitleaksScanner
from sentinel.scanners.headers import HeadersScanner
from sentinel.scanners.nmap import NmapScanner
from sentinel.scanners.pip_audit import PipAuditScanner
from sentinel.scanners.semgrep import SemgrepScanner
from sentinel.scanners.trivy import TrivyScanner
from sentinel.scanners.zap import ZAPScanner

SCANNER_REGISTRY: Dict[str, Type[BaseScanner]] = {
    "bandit": BanditScanner,
    "semgrep": SemgrepScanner,
    "pip_audit": PipAuditScanner,
    "gitleaks": GitleaksScanner,
    "nmap": NmapScanner,
    "headers": HeadersScanner,
    "trivy": TrivyScanner,
    "zap": ZAPScanner,
}

__all__ = [
    "BaseScanner",
    "BanditScanner",
    "SemgrepScanner",
    "PipAuditScanner",
    "GitleaksScanner",
    "NmapScanner",
    "HeadersScanner",
    "TrivyScanner",
    "ZAPScanner",
    "SCANNER_REGISTRY",
]
