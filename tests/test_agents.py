"""Tests for the multi-agent dispatcher + reference agents (structured output)."""
import pytest

from core.agents.dispatcher import Dispatcher
from core.agents.interface import (
    AgentFindingCandidate,
    AgentResult,
    AgentToolRequest,
)
from core.execution.models import ExecutionContext
from core.orchestrator.planner import Task


def _task(area, files=None):
    return Task(id="t1", area=area, description="d", files=files or [])


def test_dispatcher_routes_by_area():
    class StubAgent:
        name = "stub"

        def analyze(self, task):
            return AgentResult(agent=self.name, finding_candidates=[
                AgentFindingCandidate(
                    title=f"finding in {task['area']}", severity="high",
                    affected_component=task["area"], root_cause="r", confidence="low",
                )
            ])

    d = Dispatcher()
    d.register("stub", StubAgent(), areas=["backend"])
    result = d.dispatch([_task("backend")])
    assert len(result.findings) == 1
    assert result.findings[0].affected_component == "backend"


def test_dispatcher_falls_back_to_default():
    class StubAgent:
        name = "stub"

        def analyze(self, task):
            return AgentResult(agent=self.name, finding_candidates=[
                AgentFindingCandidate(title="x", severity="medium", root_cause="r")
            ])

    d = Dispatcher()
    d.register("stub", StubAgent())  # no areas -> default fallback
    result = d.dispatch([_task("unmapped-area")])
    assert len(result.findings) == 1


def test_dispatcher_dedups_across_agents():
    class AgentA:
        name = "a"

        def analyze(self, task):
            return AgentResult(agent=self.name, finding_candidates=[
                AgentFindingCandidate(title="SQLi", severity="high",
                                      affected_component="login", root_cause="unsanitized")
            ])

    class AgentB:
        name = "b"

        def analyze(self, task):
            return AgentResult(agent=self.name, finding_candidates=[
                AgentFindingCandidate(title="SQL injection", severity="critical",
                                      affected_component="login", root_cause="unsanitized")
            ])

    d = Dispatcher()
    d.register("a", AgentA(), areas=["backend"])
    d.register("b", AgentB(), areas=["frontend"])
    result = d.dispatch([_task("backend"), _task("frontend")])
    # same (component, root cause) -> deduped to one, promoted to critical
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "critical"


def test_dispatcher_collects_tool_requests():
    class StubAgent:
        name = "stub"

        def analyze(self, task):
            return AgentResult(agent=self.name, tool_requests=[
                AgentToolRequest(capability="vulnerability-scanning", target_value="https://x")
            ])

    d = Dispatcher(context=ExecutionContext("prj", "tgt", "scn"))
    d.register("stub", StubAgent(), areas=["backend"])
    result = d.dispatch([_task("backend")])
    assert len(result.tool_requests) == 1
    req = result.tool_requests[0]
    assert req.capability == "vulnerability-scanning"
    assert req.source == "agent:stub"
    # the dispatcher only produces a ToolRequest; it does NOT run it
    assert req.context.scan_id == "scn"


def test_duplicate_agent_registration_raises():
    class Stub:
        name = "s"

        def analyze(self, task):
            return AgentResult(agent="s")

    d = Dispatcher()
    d.register("s", Stub())
    with pytest.raises(ValueError):
        d.register("s", Stub())


def test_dispatcher_no_agents_returns_empty():
    d = Dispatcher()
    result = d.dispatch([_task("backend")])
    assert result.findings == []
    assert result.tool_requests == []


def test_dispatcher_supports_legacy_candidates():
    class StubAgent:
        name = "stub"

        def analyze(self, task):
            return AgentResult(agent=self.name, candidates=[{
                "title": "legacy", "severity": "high",
                "affected_component": "x", "root_cause": "r",
            }])

    d = Dispatcher()
    d.register("stub", StubAgent(), areas=["backend"])
    result = d.dispatch([_task("backend")])
    assert len(result.findings) == 1
