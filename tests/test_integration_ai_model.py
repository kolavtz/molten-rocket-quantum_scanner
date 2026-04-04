import os
import pytest

from src.services.ai.llm_client import LLMClient


@pytest.mark.skipif(os.environ.get("QSS_RUN_REAL_MODEL_TESTS") != "1", reason="Real-model integration tests disabled by default")
def test_llm_client_generate_real_model():
    # Ensure model path is set for the test runner environment
    model_path = os.environ.get("QSS_AI_MODEL_PATH")
    assert model_path, "QSS_AI_MODEL_PATH must be set to run this integration test"

    client = LLMClient()
    out = client.generate("Say hello in one sentence.", max_tokens=20, temperature=0.1)
    assert isinstance(out, str)
    assert len(out.strip()) > 0


@pytest.mark.skipif(os.environ.get("QSS_RUN_REAL_MODEL_TESTS") != "1", reason="Real-model integration tests disabled by default")
def test_llm_client_stream_generate_real_model():
    model_path = os.environ.get("QSS_AI_MODEL_PATH")
    assert model_path, "QSS_AI_MODEL_PATH must be set to run this integration test"

    client = LLMClient()
    chunks = []
    for chunk in client.stream_generate("Stream a short greeting.", max_tokens=20, temperature=0.1):
        chunks.append(chunk)
        # Don't iterate forever in case of unexpected streaming behavior
        if sum(len(c) for c in chunks) > 200:
            break
    assert len(chunks) > 0
    joined = "".join(chunks)
    assert joined.strip()
