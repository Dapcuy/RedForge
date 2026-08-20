"""Agent interface (contract) with structured output.

Any agent (Hermes, Claude, custom, local LLM) drives the platform through this
interface. Agents emit **structured** messages — never raw shell commands and
never direct runtime access:

    AgentObservation       what the agent saw/learned
    AgentDecision          what the agent decided to do
    AgentToolRequest       a request to run a capability (NOT a shell command)
    AgentFindingCandidate  a candidate finding for the Finding engine

An agent returns an ``AgentResult`` containing any mix of these. The
dispatcher turns AgentToolRequest into a ToolRequest (for the execution
service) and AgentFindingCandidate into a Finding candidate.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from ..findings.models import Confidence, Severity


@dataclass
class AgentObservation:
    """A structured observation the agent recorded about the target/task."""
    content: str
    kind: str = "general"            # general | fingerprint | finding-hint
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class AgentDecision:
    """A decision the agent made (e.g. next step, or conclude)."""
    action: str                      # e.g. "run-tool", "conclude", "continue"
    rationale: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentToolRequest:
    """An agent's request to run a capability.

    This is NOT a shell command. It names a capability (and optionally a
    preferred tool). The execution service resolves and policy-checks it.
    """
    capability: str
    tool_name: str = ""
    target_value: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentFindingCandidate:
    """A candidate finding the agent wants the Finding engine to consider."""
    title: str
    severity: str = "medium"
    confidence: str = "low"
    affected_component: str = ""
    root_cause: str = ""
    attack_path: str = ""
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class AgentResult:
    """Structured output of a single agent run."""
    agent: str
    observations: list[AgentObservation] = field(default_factory=list)
    decisions: list[AgentDecision] = field(default_factory=list)
    tool_requests: list[AgentToolRequest] = field(default_factory=list)
    finding_candidates: list[AgentFindingCandidate] = field(default_factory=list)
    # Backward-compat alias for older agents that returned dict candidates.
    candidates: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "observations": [o.__dict__ for o in self.observations],
            "decisions": [d.__dict__ for d in self.decisions],
            "tool_requests": [t.__dict__ for t in self.tool_requests],
            "finding_candidates": [f.__dict__ for f in self.finding_candidates],
            "candidates": self.candidates,
        }


class Agent(abc.ABC):
    """Base agent. A concrete agent implements ``analyze``."""

    name = "generic"

    @abc.abstractmethod
    def analyze(self, task: dict[str, Any]) -> AgentResult:
        """Analyze a task and return structured output."""


def _to_severity(value: Any) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.MEDIUM


def _to_confidence(value: Any) -> Confidence:
    try:
        return Confidence(value)
    except ValueError:
        return Confidence.LOW
