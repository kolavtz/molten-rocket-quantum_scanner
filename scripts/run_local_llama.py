"""
Quick runner to validate a local llama-cpp model with the project's LLMClient.

Usage:
  python scripts/run_local_llama.py --model PATH_TO_MODEL

This script is intentionally small and defensive: it attempts to import the
llama-cpp-python bindings and will print helpful instructions if they're
missing.
"""
from __future__ import annotations
import argparse
import os
import sys
from src.services.ai.llm_client import LLMClient


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", help="Path to local GGML model file", required=False)
    args = p.parse_args()

    if args.model:
        os.environ["QSS_AI_MODEL_PATH"] = args.model
    print("Initializing LLM client... (this may take a few seconds)")
    try:
        client = LLMClient()
    except Exception as e:
        print("Failed to initialize LLM client:", e)
        print("Make sure you have installed 'llama-cpp-python' and that the model path is correct.")
        sys.exit(1)

    prompt = "Write a single-sentence greeting:"
    try:
        print("Generating response...")
        text = client.generate(prompt=prompt, max_tokens=20, temperature=0.1)
        print("--- Response ---")
        print(text)
        print("----------------")
    except Exception as e:
        print("Generation failed:", e)
        sys.exit(2)


if __name__ == '__main__':
    main()
