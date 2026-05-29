"""
LLM configuration for the RAG security evaluation framework.

Set OPENAI_API_KEY environment variable to enable GPT-4o-mini for real experiments.
Without the key the framework falls back to the deterministic rule-based simulator,
which is labelled explicitly as "simulation" in all CSV logs.
"""
from __future__ import annotations
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class LLMConfig:
    provider: str        # "openai" | "simulation"
    model: str
    temperature: float
    max_tokens: int


def get_llm_config() -> LLMConfig:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if api_key:
        return LLMConfig(
            provider="openai",
            model="gpt-4o-mini",
            temperature=0.0,
            max_tokens=512,
        )
    return LLMConfig(
        provider="simulation",
        model="rule-based-sim-v1",
        temperature=0.0,
        max_tokens=512,
    )
