"""Hermes agent adapter.

Maps Hermes' tool-calling surface onto RedForge's Agent interface. The adapter
is a plug-in: it does not import the core, only the public interface contract.
"""
from __future__ import annotations

from typing import Any

from core.agents.interface import Agent, AgentResult


class HermesAgent(Agent):
    """Adapter for driving RedForge from Hermes.

    In a live setup, ``analyze`` delegates to Hermes' planner/analyst surface.
    For the MVP it is a thin adapter that returns no candidates (the platform
    works without it — Hermes is one possible brain, not the core).
    """

    name = "hermes"

    def __init__(self, delegate: Any = None) -> None:
        self.delegate = delegate

    def analyze(self, task: dict[str, Any]) -> AgentResult:
        if self.delegate is not None:
            return self.delegate(task)
        return AgentResult(agent=self.name, candidates=[])
