"""Tests for the multi-agent dispatcher + reference agents."""
import pytest

from core.agents.dispatcher import Dispatcher
from core.agents.interface import AgentResult
from core.orchestrator.planner import Task


def _task(area, files=None):
    return Task(id="t1", area=area, description="d", files=files or [])


def test_dispatcher_routes_by_area():
    class StubAgent:
        name = "stub"

        def analyze(self, task):
            return AgentResult(agent=self.name, candidates=[{
                "title": f"finding in {task['area']}",
                "severity": "high", "affected_component": task["area"],
                "root_cause": "r", "confidence": "low",
            }])

    d = Dispatcher()
    d.register("stub", StubAgent(), areas=["backend"])
    findings = d.dispatch([_task("backend")])
    assert len(findings) == 1
    assert findings[0].affected_component == "backend"


def test_dispatcher_falls_back_to_default():
    class StubAgent:
        name = "stub"

        def analyze(self, task):
            return AgentResult(agent=self.name, candidates=[{
                "title": "x", "severity": "medium", "root_cause": "r",
            }])

    d = Dispatcher()
    d.register("stub", StubAgent())  # no areas -> default fallback
    findings = d.dispatch([_task("unmapped-area")])
    assert len(findings) == 1


def test_dispatcher_dedups_across_agents():
    class AgentA:
        name = "a"

        def analyze(self, task):
            return AgentResult(agent=self.name, candidates=[{
                "title": "SQLi", "severity": "high",
                "affected_component": "login", "root_cause": "unsanitized",
            }])

    class AgentB:
        name = "b"

        def analyze(self, task):
            return AgentResult(agent=self.name, candidates=[{
                "title": "SQL injection", "severity": "critical",
                "affected_component": "login", "root_cause": "unsanitized",
            }])

    d = Dispatcher()
    d.register("a", AgentA(), areas=["backend"])
    d.register("b", AgentB(), areas=["frontend"])
    findings = d.dispatch([_task("backend"), _task("frontend")])
    # same (component, root cause) -> deduped to one, promoted to critical
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


def test_duplicate_agent_registration_raises():
    class Stub:
        name = "s"

        def analyze(self, task):
            return AgentResult(agent="s", candidates=[])

    d = Dispatcher()
    d.register("s", Stub())
    with pytest.raises(ValueError):
        d.register("s", Stub())


def test_dispatcher_no_agents_returns_empty():
    d = Dispatcher()
    assert d.dispatch([_task("backend")]) == []
