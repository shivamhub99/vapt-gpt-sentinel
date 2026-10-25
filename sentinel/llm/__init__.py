"""
LLM Provider Factory for VAPT-GPT Sentinel.
Selects provider (gemini, anthropic, openai, mock) based on environment configuration.
"""

import os
from typing import Dict, Optional, Type

from sentinel.llm.anthropic import AnthropicProvider
from sentinel.llm.base import LLMProvider
from sentinel.llm.gemini import GeminiProvider
from sentinel.llm.mock import MockProvider
from sentinel.llm.openai import OpenAIProvider

PROVIDER_MAP: Dict[str, Type[LLMProvider]] = {
    "mock": MockProvider,
    "gemini": GeminiProvider,
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
}


def get_llm_provider(name: Optional[str] = None) -> LLMProvider:
    """Instantiates and returns the configured LLM provider."""
    provider_name = (name or os.getenv("LLM_PROVIDER", "mock")).strip().lower()
    provider_cls = PROVIDER_MAP.get(provider_name, MockProvider)
    return provider_cls()


__all__ = [
    "LLMProvider",
    "MockProvider",
    "GeminiProvider",
    "AnthropicProvider",
    "OpenAIProvider",
    "get_llm_provider",
]
