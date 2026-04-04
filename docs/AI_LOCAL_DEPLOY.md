Local llama-cpp deployment and testing guide
=========================================

This document explains how to run a small local LLM backend (llama-cpp-python)
to power the in-repo AI assistant endpoints.

Prerequisites
-------------
- A supported GGML quantized model (for example: llm/ggml-model-q4_0.bin). See model provider for download instructions.
- Python 3.10+ and the project's virtualenv activated.

Install llama-cpp-python
-------------------------
From the project root with the virtualenv active:

```bash
pip install "llama-cpp-python>=0.1.80"  # may require a C compiler
```

Set environment variables
-------------------------
Create or update your `.env` (do NOT check secrets into source control):

```text
QSS_AI_MODEL_BACKEND=llama_cpp
QSS_AI_MODEL_PATH=/absolute/path/to/your/ggml-model-q4_0.bin
QSS_AI_MAX_TOKENS=512
QSS_AI_TEMPERATURE=0.2
QSS_AI_USE_RAG=false
QSS_RAG_DB_PATH=data/ai_rag.db
```

Quick smoke test
----------------
Run the helper script which uses the same LLMClient used by the app:

```bash
python scripts/run_local_llama.py --model /absolute/path/to/ggml-model-q4_0.bin
```

If the model loads and you get a one-line response, the local LLM is configured.

Notes
-----
- On some systems building the `llama-cpp-python` wheel may require a C toolchain.
- For streaming token-by-token output, the installed `llama-cpp-python` must support streaming APIs; otherwise the server will fall back to non-streaming behavior.
