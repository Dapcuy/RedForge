"""Integration: the orchestrator's agent reasoning loop.

Round 1: the live agent requests a tool (executed against a fake runtime).
The orchestrator feeds the tool summary back via observe().
Round 2: the agent concludes (no tool requests) -> loop stops, findings judged.

Also verifies the policy cap: llm_max_iterations bounds feedback rounds even
when the agent asks for more.
"""
from __future__ import annotations

import json
import os

from test_hermes_live import ScriptedLLM

from agents.hermes.live import HermesLiveAgent
from core.execution.service import ToolExecutionService
from core.models import RunResult, RunStatus
from core.orchestrator.scan import Orchestrator
from core.persistence.store import BlobStore, SqliteStore
from core.policy.engine import Policy, PolicyEngine
from core.tools.registry import ToolRegistry

TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "tools")

EMIT_ROUND1 = json.dumps({
    "agent": "hermes",
    "tool_requests": [
        {"capability": "vulnerability-scanning", "target_value": "http://lab.example.local"},
    ],
    "decisions": [{"action": "continue", "rationale": "initial scan"}],
})
EMIT_CONCLUDE = json.dumps({
    "agent": "hermes",
    "finding_candidates": [
        {"title": "Outdated component detected", "severity": "high",
         "confidence": "medium", "affected_component": "http://lab.example.local",
         "root_cause": "observed via scan feedback"},
    ],
    "decisions": [{"action": "conclude", "rationale": "enough evidence"}],
})


class _FakeRuntime:
    name = "fake"

    def command_for(self, tool, target, ctx, limits=None, workspace=None, args=None):
        return ["fake", tool.name]

    def run(self, tool, target, ctx, limits=None, workspace=None, args=None):
        return RunResult(
            run_id=ctx.run_id, tool=tool.name, status=RunStatus.SUCCESS,
            exit_code=0, stdout='{"scanner": "fake", "severity": "high"}',
            stderr="", tool_version="1.0",
        )

    def stop(self, run_id):
        pass

    def logs(self, run_id):
        return iter(())

    def inspect(self, run_id):
        return None


def _build(tmp_path, policy: Policy, agent: HermesLiveAgent) -> Orchestrator:
    blob = BlobStore(str(tmp_path / "blobs"))
    db = SqliteStore(str(tmp_path / "redforge.db"), blob_store=blob)
    registry = ToolRegistry()
    registry.load_dir(TOOLS_DIR)
    execution = ToolExecutionService(registry, _FakeRuntime(), PolicyEngine(policy))
    return Orchestrator(
        projects=db, targets=db, scans=db, tool_runs=db, artifacts=db,
        evidence_repo=db, findings_repo=db, execution=execution,
    ), agent


def _live_agent(responses: list[str]) -> HermesLiveAgent:
    return HermesLiveAgent(
        llm=ScriptedLLM(responses),
        capabilities=["vulnerability-scanning", "technology-detection"],
    )


def test_feedback_loop_runs_two_rounds(tmp_path):
    agent = _live_agent([EMIT_ROUND1, EMIT_CONCLUDE])
    orch, agent = _build(
        tmp_path,
        Policy(allowed_targets=["*.example.local"], external_targets=True),
        agent,
    )
    result = orch.run(
        target_value="http://lab.example.local",
        project_name="feedback-test",
        agent=agent,
    )
    assert result.status.value == "completed"
    # Round 1 executed the tool; round 2 concluded without new requests.
    assert agent.usage.calls == 2
    assert len(result.tool_runs) == 1
    # The tool summary reached the agent through the feedback channel.
    assert any("TOOL FEEDBACK" in m for m in agent._memory)
    assert "vulnerability-scanning" in str(agent._memory)
    # The round-2 candidate became a judged finding.
    assert len(result.findings) == 1
    assert result.findings[0].title == "Outdated component detected"


def test_policy_caps_feedback_rounds(tmp_path):
    # Agent wants up to 3 rounds (default), but policy allows only 1 iteration.
    agent = _live_agent([EMIT_ROUND1, EMIT_CONCLUDE, EMIT_CONCLUDE])
    assert agent.feedback_rounds >= 2
    orch, agent = _build(
        tmp_path,
        Policy(allowed_targets=["*.example.local"], external_targets=True,
               llm_max_iterations=1),
        agent,
    )
    result = orch.run(
        target_value="http://lab.example.local",
        project_name="cap-test",
        agent=agent,
    )
    assert agent.usage.calls == 1          # single round, no feedback turn
    assert len(result.tool_runs) == 1


def test_static_agent_still_works_single_round(tmp_path):
    """Agents without observe()/feedback_rounds run exactly one round."""
    from core.agents.interface import Agent, AgentFindingCandidate, AgentResult, AgentToolRequest

    class StaticAgent(Agent):
        name = "static"
        calls = 0

        def analyze(self, task):
            StaticAgent.calls += 1
            return AgentResult(
                agent=self.name,
                finding_candidates=[AgentFindingCandidate(
                    title="Static finding", severity="low",
                    affected_component="app", root_cause="static",
                )],
                tool_requests=[AgentToolRequest(
                    capability="vulnerability-scanning",
                    target_value="http://lab.example.local",
                )],
            )

    agent = StaticAgent()
    orch, agent = _build(
        tmp_path,
        Policy(allowed_targets=["*.example.local"], external_targets=True),
        agent,
    )
    result = orch.run(
        target_value="http://lab.example.local",
        project_name="static-test",
        agent=agent,
    )
    assert result.status.value == "completed"
    assert StaticAgent.calls == 1
    assert len(result.tool_runs) == 1
    assert len(result.findings) == 1
