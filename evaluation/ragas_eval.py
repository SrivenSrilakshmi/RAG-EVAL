"""
Lightweight RAGAS-style evaluation metrics.

Provides two core metrics without requiring the full `ragas` package:
  - Faithfulness:     fraction of response claims grounded in retrieved context.
  - Answer Relevancy: keyword overlap between query and response.

If the `ragas` package is installed AND an OpenAI API key is present, a
`run_ragas_eval()` function is also available for full RAGAS evaluation.
"""
from __future__ import annotations

import re
from typing import List


def _tokenize(text: str) -> set:
    return set(re.findall(r"[a-zA-Z0-9]+", text.lower()))


def faithfulness_score(response: str, context_docs: List[str]) -> float:
    """
    Lightweight faithfulness: proportion of response sentences whose content
    words overlap with the retrieved context.

    Higher is better (1.0 = fully grounded).
    """
    combined_context_tokens = _tokenize(" ".join(context_docs))
    if not combined_context_tokens:
        return 0.0

    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", response) if s.strip()]
    if not sentences:
        return 0.0

    scores = []
    for sentence in sentences:
        s_tokens = _tokenize(sentence)
        if not s_tokens:
            continue
        overlap = len(s_tokens & combined_context_tokens) / len(s_tokens)
        scores.append(overlap)

    return round(sum(scores) / len(scores), 4) if scores else 0.0


def answer_relevancy_score(query: str, response: str) -> float:
    """
    Lightweight answer relevancy: Jaccard similarity between query and response
    token sets.

    Higher is better (1.0 = response exactly mirrors query vocabulary).
    """
    q_tokens = _tokenize(query)
    r_tokens = _tokenize(response)
    if not q_tokens or not r_tokens:
        return 0.0
    intersection = q_tokens & r_tokens
    union = q_tokens | r_tokens
    return round(len(intersection) / len(union), 4)


def context_recall_score(response: str, expected_keywords: List[str]) -> float:
    """
    Proxy for context recall: fraction of expected keywords present in response.
    """
    if not expected_keywords:
        return 0.0
    lowered = response.lower()
    matched = sum(1 for kw in expected_keywords if kw.lower() in lowered)
    return round(matched / len(expected_keywords), 4)


def evaluate_row(response: str, query: str, context_docs: List[str], expected_keywords: List[str]) -> dict:
    return {
        "faithfulness": faithfulness_score(response, context_docs),
        "answer_relevancy": answer_relevancy_score(query, response),
        "context_recall": context_recall_score(response, expected_keywords),
    }
