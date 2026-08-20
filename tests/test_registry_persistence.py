"""Tests for hardened tool registry (priority, input schema, trust) + persistence fixes."""
import os

import pytest

from core.execution.models import ExecutionContext, ToolRun
from core.models import RunStatus, Tool
from core.persistence.store import SqliteStore
from core.tools.registry import ToolRegistry

TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "tools")


def _tool(name="t1", capabilities=("a",), priority=0, input_schema=None, trust=None):
    return Tool(
        name=name, domain="web", capabilities=list(capabilities),
        runtime={"image": "i", "entrypoint": name, "version": "1.0.0"},
        inputs={"target": "url"}, output={"format": "json"},
        priority=priority, input_schema=input_schema or {}, trust=trust or {},
    )


def test_resolve_capability_prefers_higher_priority():
    reg = ToolRegistry()
    reg.register(_tool("low", ("a",), priority=1))
    reg.register(_tool("high", ("a",), priority=10))
    assert reg.resolve_capability("a").name == "high"


def test_resolve_capability_deterministic_tiebreak():
    reg = ToolRegistry()
    reg.register(_tool("zeta", ("a",), priority=5))
    reg.register(_tool("alpha", ("a",), priority=5))
    assert reg.resolve_capability("a").name == "alpha"  # name tiebreak


def test_resolve_preferred_wins_over_priority():
    reg = ToolRegistry()
    reg.register(_tool("high", ("a",), priority=10))
    reg.register(_tool("low", ("a",), priority=1))
    assert reg.resolve_capability("a", preferred="low").name == "low"


def test_validate_arguments_unknown_key_rejected():
    reg = ToolRegistry()
    tool = _tool(input_schema={"path": {"type": "string"}})
    with pytest.raises(ValueError):
        reg.validate_arguments(tool, {"path": "x", "mount": "/etc"})


def test_validate_arguments_required_missing():
    reg = ToolRegistry()
    tool = _tool(input_schema={"path": {"type": "string", "required": True}})
    with pytest.raises(ValueError):
        reg.validate_arguments(tool, {})


def test_validate_arguments_type_check():
    reg = ToolRegistry()
    tool = _tool(input_schema={"path": {"type": "string"}})
    with pytest.raises(ValueError):
        reg.validate_arguments(tool, {"path": 42})


def test_validate_arguments_ok():
    reg = ToolRegistry()
    tool = _tool(input_schema={"path": {"type": "string", "required": True}})
    reg.validate_arguments(tool, {"path": "app.py"})  # no raise


def test_tool_verified_property():
    assert _tool(trust={"verified": True}).verified is True
    assert _tool(trust={"verified": False}).verified is False
    assert _tool().verified is False


def test_sqlite_restores_full_execution_context(tmp_path):
    db = SqliteStore(str(tmp_path / "db.sqlite"))
    ctx = ExecutionContext(
        project_id="prj_x", target_id="tgt_y", scan_id="scn_z",
        task_id="tsk_w", agent_run_id="arun_v",
    )
    run = ToolRun(
        id="trun_1", tool_name="nuclei", tool_version="3.3.7", capability="vuln",
        target="https://x", context=ctx, command=["docker", "run"],
        runtime="docker", status=RunStatus.SUCCESS, exit_code=0,
    )
    db.add_tool_run(run)
    got = db.get_tool_run("trun_1")
    assert got.context.project_id == "prj_x"
    assert got.context.target_id == "tgt_y"
    assert got.context.scan_id == "scn_z"
    assert got.context.task_id == "tsk_w"
    assert got.context.agent_run_id == "arun_v"
    db.close()


def test_transaction_rolls_back_on_error(tmp_path):
    db = SqliteStore(str(tmp_path / "db.sqlite"))
    ctx = ExecutionContext("prj", "tgt", "scn")
    run = ToolRun(
        id="trun_tx", tool_name="nuclei", tool_version="1", capability="v",
        target="x", context=ctx, command=[], runtime="docker",
        status=RunStatus.SUCCESS, exit_code=0,
    )
    with pytest.raises(RuntimeError), db.transaction():
        db.add_tool_run(run)
        raise RuntimeError("boom")
    # rolled back: no tool run persisted
    assert db.get_tool_run("trun_tx") is None
    db.close()


def test_transaction_commits_on_success(tmp_path):
    db = SqliteStore(str(tmp_path / "db.sqlite"))
    ctx = ExecutionContext("prj", "tgt", "scn")
    run = ToolRun(
        id="trun_ok", tool_name="nuclei", tool_version="1", capability="v",
        target="x", context=ctx, command=[], runtime="docker",
        status=RunStatus.SUCCESS, exit_code=0,
    )
    with db.transaction():
        db.add_tool_run(run)
    assert db.get_tool_run("trun_ok") is not None
    db.close()


def test_e2e_probe_manifest_has_schema_and_trust():
    reg = ToolRegistry()
    reg.load_dir(TOOLS_DIR)
    probe = reg.get("e2e-probe")
    assert probe is not None
    assert probe.verified is True
    assert "path" in probe.input_schema
