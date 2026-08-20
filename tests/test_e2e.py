"""End-to-end test: target -> profile -> skill -> agent -> tool request
-> policy -> tool -> runtime -> artifact -> evidence -> finding -> SQLite.

Uses a fake runtime (no Docker daemon) and a real SQLite store, so the whole
vertical slice is exercised deterministically in CI.
"""
import os

from core.agents.interface import Agent, AgentFindingCandidate, AgentResult, AgentToolRequest
from core.execution.service import ToolExecutionService
from core.models import RunResult, RunStatus
from core.orchestrator.scan import Orchestrator
from core.persistence.store import BlobStore, SqliteStore
from core.policy.engine import Policy, PolicyEngine
from core.tools.registry import ToolRegistry

TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "tools")


class _FakeRuntime:
    name = "fake"

    def command_for(self, tool, target, ctx, limits=None):
        return ["fake", "run", tool.name, target.value]

    def run(self, tool, target, ctx, limits=None):
        return RunResult(
            run_id=ctx.run_id, tool=tool.name, status=RunStatus.SUCCESS,
            exit_code=0, stdout='{"cve": "CVE-2024-0001", "severity": "high"}',
            stderr="", tool_version=tool.runtime.get("version", ""),
        )

    def stop(self, run_id):
        pass

    def logs(self, run_id):
        return iter(())

    def inspect(self, run_id):
        return None


class _ScanAgent(Agent):
    name = "scan"

    def analyze(self, task):
        target = task.get("target", "") or ""
        return AgentResult(
            agent=self.name,
            finding_candidates=[
                AgentFindingCandidate(
                    title="Test finding", severity="high",
                    affected_component="app", root_cause="test root cause",
                )
            ],
            tool_requests=[
                AgentToolRequest(capability="vulnerability-scanning", target_value=target)
            ],
        )


def _build_orchestrator(tmp_path):
    blob = BlobStore(str(tmp_path / "blobs"))
    db = SqliteStore(str(tmp_path / "redforge.db"), blob_store=blob)

    registry = ToolRegistry()
    registry.load_dir(TOOLS_DIR)

    # policy allows the target, so the request passes scope check
    policy = Policy(allowed_targets=["*.example.local"], external_targets=True)
    execution = ToolExecutionService(registry, _FakeRuntime(), PolicyEngine(policy))

    orch = Orchestrator(
        projects=db, targets=db, scans=db, tool_runs=db, artifacts=db,
        evidence_repo=db, findings_repo=db, execution=execution,
    )
    return orch, db


def test_end_to_end_scan(tmp_path):
    orch, db = _build_orchestrator(tmp_path)
    result = orch.run(
        target_value="https://app.example.local",
        project_name="e2e",
        agent=_ScanAgent(),
    )

    # findings persisted
    assert len(result.findings) == 1
    assert result.findings[0].title == "Test finding"

    # tool run + evidence persisted, traceable to the scan
    assert len(result.tool_runs) == 1
    run = result.tool_runs[0]
    assert run.tool_name == "nuclei"
    assert run.context.scan_id == result.context.scan_id

    assert len(result.evidence) == 1
    ev = result.evidence[0]
    assert ev.scan_id == result.context.scan_id
    assert ev.tool_run_id == run.id
    assert ev.tool == "nuclei"

    # everything reached SQLite
    assert db.get_scan(result.context.scan_id)["status"] == "completed"
    assert len(db.list_findings()) == 1
    assert len(db.list_tool_runs()) == 1
    assert len(db.list_evidence()) == 1
    assert len(db.list_artifacts()) >= 1  # stdout artifact

    db.close()


def test_e2e_out_of_scope_blocked(tmp_path):
    """A target out of policy scope is blocked before any tool runs."""
    blob = BlobStore(str(tmp_path / "blobs"))
    db = SqliteStore(str(tmp_path / "redforge.db"), blob_store=blob)
    registry = ToolRegistry()
    registry.load_dir(TOOLS_DIR)
    policy = Policy(allowed_targets=["*.example.local"], external_targets=False)
    execution = ToolExecutionService(registry, _FakeRuntime(), PolicyEngine(policy))
    orch = Orchestrator(
        projects=db, targets=db, scans=db, tool_runs=db, artifacts=db,
        evidence_repo=db, findings_repo=db, execution=execution,
    )

    import pytest

    from core.policy.engine import PolicyViolation

    with pytest.raises(PolicyViolation):
        orch.run(
            target_value="https://evil.com",
            project_name="e2e",
            agent=_ScanAgent(),
        )
    # nothing was persisted for a blocked scan (fail-closed)
    assert db.list_tool_runs() == []
    db.close()
