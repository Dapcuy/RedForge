"""Hermes agent adapter — live bridge from an external LLM brain to RedForge.

Hermes (or any LLM platform) is ONE possible brain, never the core. This
adapter maps structured input from the brain onto RedForge's Agent interface.

Live contract (EmitRequest JSON):

    {
      "agent": "hermes",
      "tool_requests": [
        {"capability": "technology-detection", "arguments": {"u": "http://..."}},
        {"capability": "vulnerability-scanning", "arguments": {"template": "/path/t.yaml"}}
      ],
      "finding_candidates": [
        {"title": "...", "severity": "high", "confidence": "medium",
         "affected_component": "...", "root_cause": "...", "evidence_refs": []}
      ],
      "observations": [{"content": "...", "kind": "fingerprint"}],
      "decisions": [{"action": "conclude", "rationale": "..."}]
    }

The adapter NEVER exposes shell access or the runtime. It only produces
structured AgentResult; the orchestrator resolves capabilities through policy,
the tool registry, and the execution service.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from core.agents.interface import (
    Agent,
    AgentDecision,
    AgentFindingCandidate,
    AgentObservation,
    AgentResult,
    AgentToolRequest,
)


def parse_emit_request(payload: str | dict[str, Any]) -> AgentResult:
    """Parse an EmitRequest JSON (or dict) into a structured AgentResult.

    Raises ValueError on malformed input. Unknown fields are ignored so the
    contract stays forward-compatible.
    """
    data = json.loads(payload) if isinstance(payload, str) else dict(payload)
    if not isinstance(data, dict):
        raise TypeError("EmitRequest must be a JSON object")

    result = AgentResult(agent=str(data.get("agent", "hermes")))

    for item in data.get("observations", []) or []:
        result.observations.append(AgentObservation(
            content=str(item.get("content", "")),
            kind=str(item.get("kind", "general")),
            evidence_refs=list(item.get("evidence_refs", []) or []),
        ))

    for item in data.get("decisions", []) or []:
        result.decisions.append(AgentDecision(
            action=str(item.get("action", "")),
            rationale=str(item.get("rationale", "")),
            data=dict(item.get("data", {}) or {}),
        ))

    for item in data.get("tool_requests", []) or []:
        result.tool_requests.append(AgentToolRequest(
            capability=str(item.get("capability", "")),
            tool_name=str(item.get("tool_name", "")),
            target_value=str(item.get("target_value", "")),
            arguments=dict(item.get("arguments", {}) or {}),
        ))

    for item in data.get("finding_candidates", []) or []:
        result.finding_candidates.append(AgentFindingCandidate(
            title=str(item.get("title", "")),
            severity=str(item.get("severity", "medium")),
            confidence=str(item.get("confidence", "low")),
            affected_component=str(item.get("affected_component", "")),
            root_cause=str(item.get("root_cause", "")),
            attack_path=str(item.get("attack_path", "")),
            evidence_refs=list(item.get("evidence_refs", []) or []),
            locations=list(item.get("locations", []) or []),
        ))

    return result


class HermesAgent(Agent):
    """Live adapter driven by an external brain.

    ``delegate`` is an optional callable ``task -> AgentResult`` (used when
    RedForge drives Hermes). ``emit_payload`` lets an external brain push a
    structured EmitRequest directly.
    """

    name = "hermes"

    def __init__(
        self,
        delegate: Callable[[dict[str, Any]], AgentResult] | None = None,
        emit_payload: str | dict[str, Any] | None = None,
    ) -> None:
        self.delegate = delegate
        self.emit_payload = emit_payload

    def analyze(self, task: dict[str, Any]) -> AgentResult:
        if self.emit_payload is not None:
            return parse_emit_request(self.emit_payload)
        if self.delegate is not None:
            return self.delegate(task)
        return AgentResult(agent=self.name)
