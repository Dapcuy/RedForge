"""Concrete LLM backends for the Hermes live agent (stdlib-only).

HTTP via ``urllib.request`` so the repository keeps its zero-dependency rule;
API keys come exclusively from environment variables, never from agent input
or EmitRequest payloads.

Backends:
- ``AnthropicLLM``    (env: ANTHROPIC_API_KEY, model default claude-sonnet-4-5)
- ``OpenAILLM``       (env: OPENAI_API_KEY,    model default gpt-5.2)
- ``OllamaLLM``       (local, no key; model default llama3.1)

All raise ``LLMError`` on transport or API failure — the live agent treats
that as a fail-closed stop, never as an empty success.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

__all__ = ["AnthropicLLM", "LLMError", "OllamaLLM", "OpenAILLM"]


class LLMError(RuntimeError):
    """A backend failed (transport, auth, or API error)."""


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str], timeout: int) -> str:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:300]
        raise LLMError(f"HTTP {exc.code} from LLM backend: {body}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LLMError(f"transport error talking to LLM backend: {exc}") from exc


class AnthropicLLM:
    """Anthropic Messages API backend."""

    def __init__(self, model: str = "claude-sonnet-4-5", timeout: int = 120) -> None:
        self.model = model
        self.timeout = timeout
        self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    def complete(self, system: str, user: str, *, json_mode: bool = True) -> str:
        if not self.api_key:
            raise LLMError("ANTHROPIC_API_KEY is not set")
        body = _post_json(
            "https://api.anthropic.com/v1/messages",
            {
                "model": self.model,
                "max_tokens": 4096,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
            {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            self.timeout,
        )
        try:
            data = json.loads(body)
            return "".join(b.get("text", "") for b in data.get("content", []))
        except (json.JSONDecodeError, AttributeError) as exc:
            raise LLMError(f"malformed Anthropic response: {body[:200]}") from exc


class OpenAILLM:
    """OpenAI-compatible Chat Completions backend (also works for compatible gateways)."""

    def __init__(
        self,
        model: str = "gpt-5.2",
        timeout: int = 120,
        base_url: str = "https://api.openai.com/v1",
    ) -> None:
        self.model = model
        self.timeout = timeout
        self.base_url = base_url.rstrip("/")
        self.api_key = os.environ.get("OPENAI_API_KEY", "")

    def complete(self, system: str, user: str, *, json_mode: bool = True) -> str:
        if not self.api_key:
            raise LLMError("OPENAI_API_KEY is not set")
        body = _post_json(
            f"{self.base_url}/chat/completions",
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                **({"response_format": {"type": "json_object"}} if json_mode else {}),
            },
            {"Authorization": f"Bearer {self.api_key}"},
            self.timeout,
        )
        try:
            data = json.loads(body)
            return data["choices"][0]["message"]["content"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"malformed OpenAI response: {body[:200]}") from exc


class OllamaLLM:
    """Local Ollama backend (no API key; keep it on localhost)."""

    def __init__(self, model: str = "llama3.1", timeout: int = 300,
                 base_url: str = "http://127.0.0.1:11434") -> None:
        self.model = model
        self.timeout = timeout
        self.base_url = base_url.rstrip("/")

    def complete(self, system: str, user: str, *, json_mode: bool = True) -> str:
        body = _post_json(
            f"{self.base_url}/api/chat",
            {
                "model": self.model,
                "stream": False,
                "format": "json" if json_mode else "",
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            {},
            self.timeout,
        )
        try:
            data = json.loads(body)
            return data["message"]["content"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LLMError(f"malformed Ollama response: {body[:200]}") from exc
