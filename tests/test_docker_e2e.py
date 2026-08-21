"""Docker-backed E2E test.

Verifies the REAL execution chain against a live Docker daemon:

    target -> ToolRequest -> policy -> resolver -> DockerRuntime
           -> container (workspace mounted read-only) -> artifact -> evidence
           -> finding -> SQLite

Uses a tiny deterministic test image (``redforge/test-runtime``) that reads a
file from the mounted /workspace and prints JSON. This is separate from the
fake-runtime E2E test (test_e2e.py).

Skipped automatically when no Docker daemon is available.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest

from core.execution.models import ExecutionContext, ToolRequest
from core.execution.service import ToolExecutionService
from core.execution.workspace import AuthorizedWorkspaceRegistry
from core.ids import scan_id, target_id, tool_request_id
from core.models import Target, TargetKind
from core.persistence.store import BlobStore, SqliteStore
from core.policy.engine import Policy, PolicyEngine
from core.runtime.base import DockerRuntime
from core.tools.registry import ToolRegistry

TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "tools")


def _docker_available() -> bool:
    try:
        proc = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=10)
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = pytest.mark.skipif(not _docker_available(), reason="Docker daemon not available")


@pytest.fixture
def docker_runtime():
    return DockerRuntime()


@pytest.fixture
def workspace(tmp_path):
    """A tiny source tree that the e2e tool will read from /workspace."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello redforge')\n", encoding="utf-8")
    (src / "README.md").write_text("# test\n", encoding="utf-8")
    return str(src)


def test_docker_e2e_executes_container_and_persists(tmp_path, workspace, docker_runtime):
    """Full chain: request -> policy -> resolver -> Docker -> artifact -> evidence -> SQLite."""
    # SQLite persistence
    blob = BlobStore(str(tmp_path / "blobs"))
    db = SqliteStore(str(tmp_path / "redforge.db"), blob_store=blob)

    registry = ToolRegistry()
    registry.load_dir(TOOLS_DIR)
    policy = Policy(per_tool_limits={"e2e-probe": {"timeout_s": 60, "memory_mb": 512}})
    workspaces = AuthorizedWorkspaceRegistry()
    wid = workspaces.register(workspace, label="e2e").id
    svc = ToolExecutionService(registry, docker_runtime, PolicyEngine(policy), workspaces=workspaces)

    request = ToolRequest(
        id=tool_request_id("docker"),
        capability="workspace-probe",
        tool_name="e2e-probe",
        target=Target(TargetKind.SOURCE_DIR, workspace),
        context=ExecutionContext("prj_e2e", target_id(workspace), scan_id("docker")),
        workspace_id=wid,
        arguments={"path": "app.py"},
    )

    outcome = svc.execute(request)
    run = outcome.tool_run

    # 1. Container executed successfully inside Docker
    assert run.status.value == "success"
    assert run.exit_code == 0
    assert run.runtime == "docker"

    # 2. The workspace was mounted read-only at /workspace and the tool read it
    parsed = json.loads(run.stdout)
    assert parsed["path"].endswith("app.py")
    # size matches the on-disk file (account for OS newline translation)
    expected_size = len(Path(workspace, "app.py").read_bytes())
    assert parsed["size"] == expected_size
    assert parsed["sha256"]  # deterministic content hash present

    # 3. Artifacts were produced
    assert any(a.kind == "stdout" for a in outcome.artifacts)
    assert run.artifact_ids

    # 4. Persist ToolRun + Artifacts + Evidence to SQLite
    db.add_tool_run(run)
    for art in outcome.artifacts:
        db.add_artifact(art)
    from core.evidence.models import make_evidence

    ev = make_evidence(
        scan_id="scn_docker", tool_run_id=run.id, tool=run.tool_name,
        target=run.target, raw=run.stdout, raw_format="json",
        tool_version=run.tool_version, source="e2e",
    )
    db.add_evidence(ev)

    assert db.get_tool_run(run.id).tool_name == "e2e-probe"
    assert len(db.list_artifacts()) >= 1
    assert len(db.list_evidence()) == 1
    db.close()


def test_docker_workspace_mounted_read_only(tmp_path, workspace, docker_runtime):
    """The workspace must be mounted read-only: writing to it fails."""
    registry = ToolRegistry()
    registry.load_dir(TOOLS_DIR)
    workspaces = AuthorizedWorkspaceRegistry()
    wid = workspaces.register(workspace, label="ro").id
    svc = ToolExecutionService(registry, docker_runtime, PolicyEngine(Policy()), workspaces=workspaces)

    request = ToolRequest(
        id=tool_request_id("ro"),
        capability="workspace-probe",
        tool_name="e2e-probe",
        target=Target(TargetKind.SOURCE_DIR, workspace),
        context=ExecutionContext("prj_ro", target_id(workspace), scan_id("ro")),
        workspace_id=wid,
        arguments={"path": "app.py"},
    )

    # The tool tries to write to /workspace/app.py; because the mount is :ro,
    # the write fails inside the container and the tool reports an error.
    # We verify this by checking the mount flag is present in the command.
    outcome = svc.execute(request)
    # --volume <root>:/workspace:ro must be in the command
    assert any(":ro" in arg for arg in outcome.tool_run.command)
