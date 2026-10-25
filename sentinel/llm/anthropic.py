"""
Anthropic LLM Provider for VAPT-GPT Sentinel.
"""

import json
import os
from typing import Any, Dict, Optional

import requests

from sentinel.llm.base import LLMProvider


class AnthropicProvider(LLMProvider):
    """Integrates Anthropic Claude API using REST endpoints."""

    provider_name = "anthropic"

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-3-5-sonnet-20241022"):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.model = model

    def explain_risk(self, finding_title: str, cwe: str, context_factors: Dict[str, Any]) -> str:
        if not self.api_key:
            from sentinel.llm.mock import MockProvider

            return MockProvider().explain_risk(finding_title, cwe, context_factors)

        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        prompt = (
            f"Explain the contextual threat of this vulnerability in 2-3 sentences:\n"
            f"Title: {finding_title} | CWE: {cwe} | Context: {json.dumps(context_factors)}"
        )
        try:
            res = requests.post(
                url,
                headers=headers,
                json={
                    "model": self.model,
                    "max_tokens": 300,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=15,
            )
            if res.status_code == 200:
                data = res.json()
                return data["content"][0]["text"].strip()
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
        from sentinel.llm.mock import MockProvider

        return MockProvider().generate_patch(
            cwe, finding_title, file_path, source_code, evidence, failure_feedback
        )
