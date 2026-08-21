"""LLM client contract (core) — implementations live outside core/.

Any LLM backend (Anthropic, OpenAI, Ollama, a local model, a scripted test
double) is ONE possible brain for an agent, exactly like Hermes. Core only
declares the minimal chat interface; concrete HTTP clients belong in
``agents/`` so the core stays dependency-free (stdlib-only).

The interface is intentionally tiny: a single ``complete`` call with a system
and a user message. Structured reasoning (loops, budgets, EmitRequest
validation) is the agent's job, not the client's.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class LLMBudget:
    """Hard limits for one agent's LLM usage (fail-stop, not best-effort).

    An agent that exhausts its budget must stop and emit a ``conclude``
    decision rather than silently continuing.
    """

    max_llm_calls: int = 8
    max_tool_requests: int = 20


@runtime_checkable
class LLMClient(Protocol):
    """Minimal chat interface for agent backends."""

    def complete(self, system: str, user: str, *, json_mode: bool = True) -> str:
        """Return the assistant message text for (system, user).

        ``json_mode`` asks the backend to constrain decoding to JSON when it
        supports it; callers must still validate the output themselves.
        """
        ...  # pragma: no cover


@dataclass
class LLMUsage:
    """Running usage counters for observability (no secrets, ever)."""

    calls: int = 0
    tool_requests_emitted: int = 0
    rejected_responses: int = 0
    errors: list[str] = field(default_factory=list)
