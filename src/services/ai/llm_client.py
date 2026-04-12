"""
Lightweight LLM client abstraction.
Supports either a local llama-cpp / gpt4all backend or a remote HTTP AI server
configured via AI_SERVER_URL. The remote HTTP server is called with a JSON
payload similar to the example curl in the user's request:

  POST {AI_SERVER_URL}/api/v1/chat
  Content-Type: application/json
  { "model": "...", "system_prompt": "...", "input": "..." }

Environment:
  AI_SERVER_URL (optional) - if set the client will call this remote server
  AI_SERVER_API_KEY (optional) - Bearer/X-API-Key header for remote server
  QSS_AI_MODEL_BACKEND (llama_cpp|gpt4all) - local backend fallback
  QSS_AI_MODEL_PATH (path to model file)
  QSS_AI_MAX_TOKENS
  QSS_AI_TEMPERATURE
  QSS_AI_SYSTEM_PROMPT
"""
from __future__ import annotations
import os
import logging
from typing import Optional, Iterator

import requests

logger = logging.getLogger(__name__)


class LLMClient:
    def __init__(self):
        # Remote HTTP AI server takes precedence when configured
        self.remote_url = os.environ.get("AI_SERVER_URL")
        if self.remote_url:
            self.backend = "remote_http"
        else:
            self.backend = os.environ.get("QSS_AI_MODEL_BACKEND", "llama_cpp")

        self.model_path = os.environ.get("QSS_AI_MODEL_PATH", "models/llama-7b-q4_0.bin")
        self.max_tokens = int(os.environ.get("QSS_AI_MAX_TOKENS", "512"))
        self.temperature = float(os.environ.get("QSS_AI_TEMPERATURE", "0.2"))
        self._client = None

        if self.backend == "remote_http":
            # No local client to initialize for remote backend
            logger.info("LLMClient: configured to use remote AI server at %s", self.remote_url)
            self._client = None

        elif self.backend == "llama_cpp":
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

        # Remote HTTP request
        if self.backend == "remote_http":
            return self._remote_generate(prompt=prompt, max_tokens=max_tokens, temperature=temperature)

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

    def _remote_generate(self, prompt: str, max_tokens: Optional[int], temperature: Optional[float]) -> str:
        """
        Call an external HTTP AI server using configuration from the environment.
        Tries a few common endpoint paths and attempts to extract a sensible
        text reply from returned JSON.
        """
        url_base = (self.remote_url or "").rstrip("/")
        if not url_base:
            raise RuntimeError("AI_SERVER_URL not configured for remote_http backend")

        model = os.environ.get("QSS_AI_REMOTE_MODEL") or os.environ.get("QSS_AI_MODEL_BACKEND") or "liquid/lfm2.5-1.2b"
        system_prompt = os.environ.get("QSS_AI_SYSTEM_PROMPT", "")
        api_key = os.environ.get("AI_SERVER_API_KEY") or os.environ.get("QSS_AI_SERVER_API_KEY")

        payload = {
            "model": model,
            "system_prompt": system_prompt,
            "input": prompt,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
            headers["X-API-Key"] = api_key

        # Candidate endpoint paths to try (in order)
        candidate_paths = [
            "/api/v1/chat",
            "/api/v1/chat/completions",
            "/v1/chat",
            "/v1/chat/completions",
        ]

        last_err = None
        for path in candidate_paths:
            url = f"{url_base}{path}"
            try:
                resp = requests.post(url, json=payload, headers=headers, timeout=30)
            except Exception as e:
                logger.debug("LLMClient: remote request to %s failed: %s", url, e)
                last_err = e
                continue

            if not resp.ok:
                logger.debug("LLMClient: remote server %s returned status %s", url, resp.status_code)
                last_err = RuntimeError(f"Remote AI server returned status {resp.status_code}")
                continue

            try:
                data = resp.json()
            except Exception:
                # Non-JSON: return raw text
                return resp.text

            # Heuristics to locate the assistant text in various response shapes
            if isinstance(data, str):
                return data
            if isinstance(data, dict):
                # Common keys
                for k in ("output", "answer", "result", "text"):
                    if k in data and isinstance(data[k], str):
                        return data[k]

                # OpenAI-style
                choices = data.get("choices") or data.get("outputs") or []
                if isinstance(choices, list) and choices:
                    first = choices[0]
                    if isinstance(first, dict):
                        # {text: "..."}
                        if "text" in first and isinstance(first["text"], str):
                            return first["text"]
                        # {message: {content: "..."}}
                        msg = first.get("message") or first.get("delta")
                        if isinstance(msg, dict):
                            cont = msg.get("content") or msg.get("text")
                            if isinstance(cont, str):
                                return cont
                        # some APIs return {choices: [{content: "..."}]}
                        if "content" in first and isinstance(first["content"], str):
                            return first["content"]

                # Some servers nest result under data->output
                if "data" in data and isinstance(data["data"], dict):
                    inner = data["data"]
                    for k in ("output", "answer", "result", "text"):
                        if k in inner and isinstance(inner[k], str):
                            return inner[k]

            # If we reach here, couldn't extract a text answer from this endpoint
            last_err = RuntimeError("Unsupported response structure from remote AI server")

        # If all endpoints failed, raise the last error
        raise RuntimeError(f"Remote AI server request failed: {last_err}")

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

        # Remote HTTP backend: no streaming guaranteed; fall back to a single full
        # text result.
        if self.backend == "remote_http":
            try:
                text = self.generate(prompt=prompt, max_tokens=max_tokens, temperature=temperature)
                yield text
                return
            except Exception as e:
                logger.exception("remote_http generation error: %s", e)
                raise

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
