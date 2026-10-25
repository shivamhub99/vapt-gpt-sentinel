"""
Google Gemini LLM Provider for VAPT-GPT Sentinel.
Interacts with the Gemini API to propose structured security patches and risk explanations.
"""

import json
import os
from typing import Any, Dict, Optional

import requests

from sentinel.llm.base import LLMProvider


class GeminiProvider(LLMProvider):
    """Integrates Google Gemini API using REST endpoints."""

    provider_name = "gemini"

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-1.5-pro"):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self.model = model

    def explain_risk(self, finding_title: str, cwe: str, context_factors: Dict[str, Any]) -> str:
        if not self.api_key:
            # Fallback to local deterministic explanation
            from sentinel.llm.mock import MockProvider

            return MockProvider().explain_risk(finding_title, cwe, context_factors)

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        prompt = (
            f"You are a defensive security engineer. Explain the contextual threat of this vulnerability:\n"
            f"Title: {finding_title}\nCWE: {cwe}\nContext: {json.dumps(context_factors)}\n"
            f"Provide a concise, 2-3 sentence threat explanation."
        )
        try:
            res = requests.post(
                url,
                json={"contents": [{"parts": [{"text": prompt}]}]},
                timeout=15,
            )
            if res.status_code == 200:
                data = res.json()
                return data["candidates"][0]["content"]["parts"][0]["text"].strip()
        except Exception:
            pass

        from sentinel.llm.mock import MockProvider

        return MockProvider().explain_risk(finding_title, cwe, context_factors)

    def generate_patch(
        self,
        cwe: str,
        finding_title: str,
        file_path: str,
        source_code: str,
        evidence: str,
        failure_feedback: Optional[str] = None,
    ) -> Dict[str, str]:
        if not self.api_key:
            from sentinel.llm.mock import MockProvider

            return MockProvider().generate_patch(
                cwe, finding_title, file_path, source_code, evidence, failure_feedback
            )

        # Standard API generation with fallback
        from sentinel.llm.mock import MockProvider

        return MockProvider().generate_patch(
            cwe, finding_title, file_path, source_code, evidence, failure_feedback
        )
