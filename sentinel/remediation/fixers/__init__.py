"""
Specialized Remediation Fixers for VAPT-GPT Sentinel.
"""

from typing import List, Type

from sentinel.remediation.fixers.base import BaseFixer
from sentinel.remediation.fixers.deps import DependencyFixer
from sentinel.remediation.fixers.headers import HeadersFixer
from sentinel.remediation.fixers.secrets import SecretsFixer
from sentinel.remediation.fixers.sqli import SQLInjectionFixer
from sentinel.remediation.fixers.xss import XSSFixer

FIXER_CLASSES: List[Type[BaseFixer]] = [
    SQLInjectionFixer,
    XSSFixer,
    SecretsFixer,
    DependencyFixer,
    HeadersFixer,
]

__all__ = [
    "BaseFixer",
    "SQLInjectionFixer",
    "XSSFixer",
    "SecretsFixer",
    "DependencyFixer",
    "HeadersFixer",
    "FIXER_CLASSES",
]
