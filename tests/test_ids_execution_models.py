"""Tests for stable IDs and execution models (P0 hardening)."""
from core.execution.models import (
    Artifact,
    ExecutionContext,
    ResourceLimits,
    ToolRun,
)
from core.ids import (
    agent_run_id,
    artifact_id,
    evidence_id,
    finding_id,
    new_id,
    project_id,
    scan_id,
    target_id,
    task_id,
    tool_request_id,
    tool_run_id,
)


def test_ids_are_typed_and_stable():
    assert project_id("p").startswith("prj_")
    assert target_id("t").startswith("tgt_")
    assert scan_id("s").startswith("scn_")
    assert task_id("k").startswith("tsk_")
    assert agent_run_id("a").startswith("arun_")
    assert tool_run_id("r").startswith("trun_")
    assert tool_request_id("q").startswith("req_")
    assert artifact_id("x").startswith("art_")
    assert evidence_id("e").startswith("ev_")
    assert finding_id("f").startswith("fnd_")


def test_ids_deterministic_with_seed():
    assert new_id("project", "a", "b") == new_id("project", "a", "b")
    assert new_id("project", "a", "b") != new_id("project", "a", "c")


def test_ids_random_without_seed():
    assert new_id("project") != new_id("project")


def test_execution_context_roundtrip():
    ctx = ExecutionContext(
        project_id="prj_1", target_id="tgt_1", scan_id="scn_1",
        task_id="tsk_1", agent_run_id="arun_1",
    )
    d = ctx.to_dict()
    assert d["project_id"] == "prj_1"
    assert d["scan_id"] == "scn_1"


def test_resource_limits_defaults_conservative():
    rl = ResourceLimits()
    assert rl.read_only_fs is True
    assert rl.network == "none"
    assert rl.memory_mb == 512


def test_resource_limits_from_dict():
    rl = ResourceLimits.from_dict({"memory_mb": 1024, "network": "bridge", "read_only_fs": False})
    assert rl.memory_mb == 1024
    assert rl.network == "bridge"
    assert rl.read_only_fs is False


def test_tool_run_to_dict():
    from core.models import RunStatus

    run = ToolRun(
        id="trun_1", tool_name="nuclei", tool_version="3.3.0", capability="vulnerability-scanning",
        target="https://x", context=ExecutionContext("prj", "tgt", "scn"),
        command=["docker", "run", "nuclei"], runtime="docker", status=RunStatus.SUCCESS, exit_code=0,
    )
    d = run.to_dict()
    assert d["status"] == "success"
    assert d["tool_name"] == "nuclei"


def test_artifact_to_dict():
    a = Artifact(id="art_1", tool_run_id="trun_1", kind="stdout", format="text", content="hello")
    d = a.to_dict()
    assert d["kind"] == "stdout"
    assert d["content"] == "hello"
