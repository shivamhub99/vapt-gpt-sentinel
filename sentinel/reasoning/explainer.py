"""
Threat Reasoning and Explanation Engine for VAPT-GPT Sentinel.
Queries configured LLM provider to explain why a vulnerability presents operational threat
within the application's specific deployment context.
"""

from typing import Optional

from sentinel.core.schemas import ContextFactors, Finding
from sentinel.llm import LLMProvider, get_llm_provider


class ThreatExplainer:
    """Generates human-readable risk rationales using LLM reasoning."""

    def __init__(self, provider: Optional[LLMProvider] = None):
        self.provider = provider or get_llm_provider()

    def explain(self, finding: Finding, factors: ContextFactors) -> str:
        """
        Produces threat explanation without modifying the deterministic risk score.
        """
        factors_dict = factors.model_dump()
        try:
            explanation = self.provider.explain_risk(
                finding_title=finding.title,
                cwe=finding.cwe,
                context_factors=factors_dict,
            )
            return explanation
        except Exception:
            # Deterministic fallback
            return (
                f"Threat Rationale: {finding.title} ({finding.cwe}) is situated in a component "
                f"with data sensitivity '{factors.data_sensitivity}' (reachability={factors.reachability}). "
                f"Exploitation threatens the underlying asset security boundaries."
            )


threat_explainer = ThreatExplainer()
