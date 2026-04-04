"""
Lightweight LLM client abstraction.
Defaults to a local llama-cpp-python backend if available.
Environment:
  QSS_AI_MODEL_BACKEND (llama_cpp|gpt4all)
  QSS_AI_MODEL_PATH (path to model file)
  QSS_AI_MAX_TOKENS
  QSS_AI_TEMPERATURE
"""
from __future__ import annotations
import os
import logging
from typing import Optional
from typing import Iterator

logger = logging.getLogger(__name__)


class LLMClient:
    def __init__(self):
        self.backend = os.environ.get("QSS_AI_MODEL_BACKEND", "llama_cpp")
        self.model_path = os.environ.get("QSS_AI_MODEL_PATH", "models/llama-7b-q4_0.bin")
        self.max_tokens = int(os.environ.get("QSS_AI_MAX_TOKENS", "512"))
        self.temperature = float(os.environ.get("QSS_AI_TEMPERATURE", "0.2"))
        self._client = None

        if self.backend == "llama_cpp":
            try:
                from llama_cpp import Llama  # type: ignore
                self._client = Llama(model_path=self.model_path)
                logger.info("LLMClient: initialized llama-cpp backend")
            except Exception as e:
                logger.warning("LLMClient: failed to initialize llama-cpp backend: %s", e)
                self._client = None
        elif self.backend == "gpt4all":
            try:
                from gpt4all import GPT4All  # type: ignore
                self._client = GPT4All(model=self.model_path)
                logger.info("LLMClient: initialized gpt4all backend")
            except Exception as e:
                logger.warning("LLMClient: failed to initialize gpt4all backend: %s", e)
                self._client = None
        else:
            logger.warning("LLMClient: unknown backend '%s'", self.backend)

    def generate(self, prompt: str, max_tokens: Optional[int] = None, temperature: Optional[float] = None) -> str:
        if max_tokens is None:
            max_tokens = self.max_tokens
        if temperature is None:
            temperature = self.temperature

        if not self._client:
            raise RuntimeError(
                "LLM backend not initialized. Set QSS_AI_MODEL_BACKEND/QSS_AI_MODEL_PATH and install dependencies."
            )

        if self.backend == "llama_cpp":
            try:
                # llama-cpp-python: create(...) returns dict with 'choices' -> [{'text': '...'}]
                resp = self._client.create(prompt=prompt, max_tokens=max_tokens, temperature=temperature)
                choices = resp.get("choices") or []
                text = ""
                if choices:
                    text = choices[0].get("text", "") or choices[0].get("message", {}).get("content", "")
                return text.strip()
            except Exception as e:
                logger.exception("llama_cpp generation error: %s", e)
                raise
        elif self.backend == "gpt4all":
            try:
                # gpt4all generate may vary by version
                text = self._client.generate(prompt)
                return (text or "").strip()
            except Exception as e:
                logger.exception("gpt4all generation error: %s", e)
                raise
        else:
            raise RuntimeError("Unsupported LLM backend: %s" % self.backend)

    def stream_generate(self, prompt: str, max_tokens: Optional[int] = None, temperature: Optional[float] = None) -> Iterator[str]:
        """
        Generator that yields partial text chunks from the underlying LLM if the backend
        supports streaming. Falls back to yielding the full text once if streaming isn't
        available for the selected backend.
        """
        if max_tokens is None:
            max_tokens = self.max_tokens
        if temperature is None:
            temperature = self.temperature

        if not self._client:
            raise RuntimeError(
                "LLM backend not initialized. Set QSS_AI_MODEL_BACKEND/QSS_AI_MODEL_PATH and install dependencies."
            )

        # Try llama-cpp-python streaming APIs first
        if self.backend == "llama_cpp":
            try:
                # Newer versions of llama-cpp-python may support a streaming `create(..., stream=True)`
                # which yields incremental chunks. Try a few common interfaces and fall back to
                # non-streaming generation when none are available.
                create_fn = getattr(self._client, "create", None)
                if callable(create_fn):
                    try:
                        # Some versions return an iterator when stream=True
                        for chunk in create_fn(prompt=prompt, max_tokens=max_tokens, temperature=temperature, stream=True):
                            if isinstance(chunk, dict):
                                text = chunk.get("text") or chunk.get("content") or ""
                            else:
                                text = str(chunk or "")
                            yield text
                        return
                    except TypeError:
                        # create(...) may not accept `stream` - try other fallbacks below
                        pass

                # Try a generic `stream` method if present
                stream_fn = getattr(self._client, "stream", None)
                if callable(stream_fn):
                    for chunk in stream_fn(prompt=prompt, max_tokens=max_tokens, temperature=temperature):
                        yield str(chunk or "")
                    return

            except Exception as e:
                logger.exception("llama_cpp streaming error: %s", e)
                # Fall through to non-streaming fallback

            # Non-streaming fallback
            text = self.generate(prompt=prompt, max_tokens=max_tokens, temperature=temperature)
            yield text
            return

        # gpt4all and other backends: no standard streaming API supported here; fallback
        if self.backend == "gpt4all":
            try:
                # Some gpt4all bindings support callback-based streaming; we don't assume it here.
                text = self.generate(prompt=prompt, max_tokens=max_tokens, temperature=temperature)
                yield text
                return
            except Exception as e:
                logger.exception("gpt4all streaming/generation error: %s", e)
                raise

        # Unsupported backend streaming
        raise RuntimeError("Unsupported LLM backend for streaming: %s" % self.backend)
