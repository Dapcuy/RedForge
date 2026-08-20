"""Dispatcher: fan tasks out to domain agents, aggregate into Finding engine.

The multi-agent model:

                    Orchestrator
                         |
         +---------------+---------------+
         |               |               |
    Recon Agent     Code Agent     Web3 Agent
         |               |               |
      Evidence       Evidence        Evidence
         |               |               |
         +---------------+---------------+
                         |
                       Judge

The dispatcher routes each task to the agent registered for its area, collects
AgentResult candidates, and feeds them into the Finding engine (dedup +
correlation + judge).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..findings.engine import FindingEngine
from .interface import Agent, AgentResult, _to_confidence, _to_severity


@dataclass
class AgentSpec:
    """A named agent bound to one or more analysis areas."""
    name: str
    agent: Agent
    areas: list[str] = field(default_factory=list)


class Dispatcher:
    def __init__(self, engine: FindingEngine | None = None) -> None:
        self.engine = engine or FindingEngine()
        self._agents: dict[str, Agent] = {}
        self._areas: dict[str, str] = {}  # area -> agent name

    def register(self, name: str, agent: Agent, areas: list[str] | None = None) -> None:
        if name in self._agents:
            raise ValueError(f"duplicate agent name: {name}")
        self._agents[name] = agent
        for area in areas or []:
            self._areas[area] = name

    def default_agent(self) -> str | None:
        """Fallback agent for areas with no dedicated agent."""
        return next(iter(self._agents), None)

    def _route(self, area: str) -> str | None:
        return self._areas.get(area, self.default_agent())

    def dispatch(self, tasks: list[Any]) -> list[Any]:
        """Route tasks to agents, collect candidates, and judge findings."""
        for task in tasks:
            area = getattr(task, "area", "config")
            agent_name = self._route(area)
            if agent_name is None:
                continue
            agent = self._agents[agent_name]
            result = agent.analyze(task.to_dict() if hasattr(task, "to_dict") else task)
            for cand in result.candidates:
                self.engine.add_candidate(
                    title=cand.get("title", "untitled"),
                    severity=_to_severity(cand.get("severity", "medium")),
                    affected_component=cand.get("affected_component", ""),
                    root_cause=cand.get("root_cause", ""),
                    confidence=_to_confidence(cand.get("confidence", "low")),
                )
        return self.engine.judge()

    @property
    def agents(self) -> list[str]:
        return list(self._agents)
