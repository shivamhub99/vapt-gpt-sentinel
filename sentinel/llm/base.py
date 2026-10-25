"""
LLM Provider Abstraction Interface for VAPT-GPT Sentinel.
Defines abstract interface for generating structured security explanations and unified diff patches.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class LLMProvider(ABC):
    """Abstract interface for LLM connectors (Gemini, Anthropic, OpenAI, Mock)."""

    provider_name: str = "base"

    @abstractmethod
    def explain_risk(self, finding_title: str, cwe: str, context_factors: Dict[str, Any]) -> str:
        """Generates a human-readable threat explanation justifying contextual risk."""

    @abstractmethod
    def generate_patch(
        self,
        cwe: str,
        finding_title: str,
        file_path: str,
        source_code: str,
        evidence: str,
        failure_feedback: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Requests a structured unified diff patch and rationale.
        Returns dict with keys: 'diff' and 'rationale'.
        """
