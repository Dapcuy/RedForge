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

The dispatcher routes each task to the agent registered for its area. It
collects structured AgentResult output:

- ``finding_candidates`` -> fed into the Finding engine (dedup + judge).
- ``tool_requests`` -> converted into ToolRequest (handled by the execution
  service; the dispatcher never runs tools itself).
- legacy ``candidates`` (dicts) -> still accepted for backward compatibility.

Agents never invoke the runtime directly. The dispatcher only hands ToolRequest
objects back to the caller, which routes them through the Tool Execution Service.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..execution.models import ExecutionContext, ToolRequest
from ..findings.engine import FindingEngine
from ..ids import tool_request_id
from .interface import (
    Agent,
    AgentFindingCandidate,
    AgentResult,
    AgentToolRequest,
    _to_confidence,
    _to_severity,
)


@dataclass
class AgentSpec:
    """A named agent bound to one or more analysis areas."""
    name: str
    agent: Agent
    areas: list[str] = field(default_factory=list)


@dataclass
class DispatchResult:
    """Findings judged so far + tool requests the agents want to run."""
    findings: list[Any] = field(default_factory=list)
    tool_requests: list[ToolRequest] = field(default_factory=list)
    observations: list[Any] = field(default_factory=list)


class Dispatcher:
    def __init__(self, engine: FindingEngine | None = None, context: ExecutionContext | None = None) -> None:
        self.engine = engine or FindingEngine()
        self.context = context
        self._agents: dict[str, Agent] = {}
        self._areas: dict[str, str] = {}  # area -> agent name

    def register(self, name: str, agent: Agent, areas: list[str] | None = None) -> None:
        if name in self._agents:
            raise ValueError(f"duplicate agent name: {name}")
        self._agents[name] = agent
        for area in areas or []:
            self._areas[area] = name

    def default_agent(self) -> str | None:
        return next(iter(self._agents), None)

    def _route(self, area: str) -> str | None:
        return self._areas.get(area, self.default_agent())

    def _ingest_finding_candidate(self, cand: AgentFindingCandidate) -> None:
        self.engine.add_candidate(
            title=cand.title,
            severity=_to_severity(cand.severity),
            affected_component=cand.affected_component,
            root_cause=cand.root_cause,
            confidence=_to_confidence(cand.confidence),
        )

    def _ingest_legacy_candidates(self, result: AgentResult) -> None:
        for cand in result.candidates:
            self.engine.add_candidate(
                title=cand.get("title", "untitled"),
                severity=_to_severity(cand.get("severity", "medium")),
                affected_component=cand.get("affected_component", ""),
                root_cause=cand.get("root_cause", ""),
                confidence=_to_confidence(cand.get("confidence", "low")),
            )

    def _to_tool_request(self, tr: AgentToolRequest, task: Any, agent_name: str) -> ToolRequest:
        from ..models import Target, TargetKind

        target_value = tr.target_value or getattr(task, "target", "") or ""
        target = Target(TargetKind.URL, target_value) if target_value else Target(TargetKind.SOURCE_DIR, "")
        ctx = self.context or ExecutionContext(
            project_id="", target_id="", scan_id="",
        )
        return ToolRequest(
            id=tool_request_id("agent", self.context.scan_id if self.context else "", tr.capability),
            capability=tr.capability,
            target=target,
            context=ctx,
            tool_name=tr.tool_name,
            arguments=tr.arguments,
            source=f"agent:{agent_name}",
        )

    def dispatch(self, tasks: list[Any]) -> DispatchResult:
        """Route tasks to agents; return findings + tool requests."""
        out = DispatchResult()
        for task in tasks:
            area = getattr(task, "area", "config")
            agent_name = self._route(area)
            if agent_name is None:
                continue
            agent = self._agents[agent_name]
            result = agent.analyze(task.to_dict() if hasattr(task, "to_dict") else task)

            out.observations.extend(result.observations)

            for cand in result.finding_candidates:
                self._ingest_finding_candidate(cand)

            self._ingest_legacy_candidates(result)

            for tr in result.tool_requests:
                out.tool_requests.append(self._to_tool_request(tr, task, agent_name))

        out.findings = self.engine.judge()
        return out

    @property
    def agents(self) -> list[str]:
        return list(self._agents)
