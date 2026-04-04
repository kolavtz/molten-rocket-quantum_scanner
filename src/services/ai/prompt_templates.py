"""
Prompt templates and helpers for CBOM assistant.
Keep prompts short and include instructions to be concise and cite sources.
"""
from __future__ import annotations
from typing import Optional


def build_prompt_for_query(query: str, context: str, max_length: int = 1024) -> str:
    """
    Build a compact prompt that gives the LLM relevant CBOM context and the user's question.
    The retriever should already have limited the context to fit small LMs.
    """
    if not isinstance(context, str):
        context = str(context or "")

    prompt = (
        "You are QuantumShield assistant — an expert that explains cryptographic inventory (CBOM) telemetry.\n"
        "Use only the provided context to answer the user's question. If the context lacks data, say that you don't have enough information and suggest how to obtain it.\n"
        "Be concise (aim for 3–5 short paragraphs) and include a short 'Sources' bullet list referencing which KPI or sample entry you used.\n\n"
        "Context:\n"
        f"{context}\n\n"
        "User question:\n"
        f"{query}\n\n"
        "Answer:"
    )

    # Trim to max_length (naive; prefer better token trimming in future)
    if len(prompt) > max_length:
        # keep tail of user question and cut context if needed
        q_part = f"\nUser question:\n{query}\n\nAnswer:"
        ctx_allowed = max(0, max_length - len(q_part))
        prompt = prompt[:ctx_allowed] + q_part
    return prompt
