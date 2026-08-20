"""Agent interface (contract).

Any agent (Hermes, Claude, custom, local LLM) can drive the platform as long
as it implements this interface. Agents consume a plan/task and return
candidate findings, which the Finding engine dedups and judges.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from ..findings.models import Confidence, Severity


@dataclass
class AgentResult:
    agent: str
    candidates: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"agent": self.agent, "candidates": self.candidates}


class Agent(abc.ABC):
    """Base agent. A concrete agent implements ``analyze``."""

    name = "generic"

    @abc.abstractmethod
    def analyze(self, task: dict[str, Any]) -> AgentResult:
        """Analyze a task and return candidate findings.

        Each candidate is a dict with keys:
            title, severity, affected_component, root_cause, confidence
        Severity/confidence are the string values from the Finding enums.
        """


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
