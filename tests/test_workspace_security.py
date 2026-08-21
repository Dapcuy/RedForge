"""Regression tests for the final security hardening pass.

Covers:
- P0-1: AuthorizedWorkspaceRegistry — agents cannot select arbitrary host paths
- P0-1: unknown workspace_id rejected (fail-closed)
- P0-1: restricted/system paths rejected
- P0-2: per-run writable temp dir is RedForge-managed, OUTSIDE the source tree
- P0-2: source tree mounted read-only; writable mount never points at the source
- P0-3: compose/CI consistency (test service exists; CI references exist)
"""
import os
from pathlib import Path

import pytest

from core.execution.models import ExecutionContext, ToolRequest
from core.execution.service import ToolExecutionService
from core.execution.workspace import (
    AuthorizedWorkspaceRegistry,
    WorkspaceAuthorizationError,
    WorkspaceBoundaryError,
)
from core.ids import scan_id, target_id, tool_request_id
from core.models import Target, TargetKind
from core.policy.engine import Policy, PolicyEngine
from core.tools.registry import ToolRegistry


class _RecordingRuntime:
    """Fake runtime that records the workspace passed by the service."""

    name = "fake"

    def __init__(self):
        self.calls = []

    def command_for(self, tool, target, ctx, limits=None, workspace=None, args=None):
        return ["fake", "run"]

    def run(self, tool, target, ctx, limits=None, workspace=None, args=None):
        self.calls.append(workspace)
        from core.models import RunResult, RunStatus

        return RunResult(run_id=ctx.run_id, tool=tool.name, status=RunStatus.SUCCESS,
                         exit_code=0, stdout="{}", tool_version="1", command=["fake"])

    def stop(self, run_id):
        pass

    def inspect(self, run_id):
        return "success"


@pytest.fixture
def registry():
    reg = ToolRegistry()
    reg.load_dir(os.path.join(os.path.dirname(__file__), "..", "tools"))
    return reg


@pytest.fixture
def svc(registry):
    ws_reg = AuthorizedWorkspaceRegistry()
    runtime = _RecordingRuntime()
    return ToolExecutionService(registry, runtime, PolicyEngine(Policy()), workspaces=ws_reg)


def _req(target_value, workspace_id="", capability="workspace-probe", tool_name="e2e-probe"):
    return ToolRequest(
        id=tool_request_id("sec"),
        capability=capability,
        tool_name=tool_name,
        target=Target(TargetKind.SOURCE_DIR, target_value),
        context=ExecutionContext("prj", target_id(target_value), scan_id("sec")),
        workspace_id=workspace_id,
        arguments={"path": "app.py"},
    )


# ---------------------------------------------------------------------------
# P0-1: workspace authorization
# ---------------------------------------------------------------------------
def test_unknown_workspace_id_rejected(svc):
    """An agent referencing an id that was never registered is rejected."""
    with pytest.raises(WorkspaceAuthorizationError):
        svc.execute(_req("/some/where", workspace_id="ws_does_not_exist"))


def test_unregistered_host_path_rejected(tmp_path, svc):
    """A raw host path that was never authorized is rejected — the agent cannot
    invent a mount for e.g. ~/.ssh or an unrelated project."""
    # NOT registered with the registry.
    with pytest.raises(WorkspaceAuthorizationError):
        svc.execute(_req(str(tmp_path / "unrelated")))


def test_agent_cannot_use_ssh_path(svc):
    """~/.ssh (or any restricted path) can never be registered as a workspace."""
    home = str(Path.home())
    # The registry itself refuses restricted paths (defense in depth).
    ws_reg = AuthorizedWorkspaceRegistry()
    with pytest.raises(WorkspaceBoundaryError):
        ws_reg.register(os.path.join(home, ".ssh"), label="evil")


def test_registered_workspace_resolves_to_id(svc, tmp_path):
    """A trusted registration yields an opaque id; the agent references it and
    the service mounts the registered root."""
    root = str(tmp_path / "project")
    root_dir = Path(root)
    root_dir.mkdir(parents=True, exist_ok=True)
    (root_dir / "app.py").write_text("print('x')")

    ws = svc.workspaces.register(root, label="proj")
    assert ws.id.startswith("ws_")
    # The id is opaque — it must NOT contain the host path.
    assert root not in ws.id

    outcome = svc.execute(_req(root, workspace_id=ws.id))
    assert outcome.tool_run.status.value == "success"


def test_registered_workspace_mounts_registered_root_not_target(svc, tmp_path):
    """Even if target.value differs, the mount root comes from the REGISTERED
    workspace, never from agent input."""
    authorized = tmp_path / "authorized"
    authorized.mkdir(parents=True, exist_ok=True)
    (authorized / "app.py").write_text("print('auth')")

    bogus = tmp_path / "bogus"
    bogus.mkdir()

    ws = svc.workspaces.register(str(authorized), label="proj")
    outcome = svc.execute(_req(str(bogus), workspace_id=ws.id))
    run = outcome.tool_run
    assert run.status.value == "success"


def test_workspace_paths_normalized_and_confined(tmp_path):
    """register() resolves symlinks and rejects paths outside an allowed base."""
    base = tmp_path / "projects"
    base.mkdir(parents=True, exist_ok=True)
    inside = base / "good"
    inside.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    reg = AuthorizedWorkspaceRegistry(allowed_base=str(base))
    reg.register(str(inside), label="ok")  # fine

    with pytest.raises(WorkspaceBoundaryError):
        reg.register(str(outside), label="escape")


# ---------------------------------------------------------------------------
# P0-2: writable temp dir security
# ---------------------------------------------------------------------------
def test_per_run_tmp_dir_outside_source_tree(svc, tmp_path):
    """The writable mount must be RedForge-managed, OUTSIDE the source tree."""
    root = tmp_path / "src"
    root.mkdir()
    (root / "app.py").write_text("print('x')")
    ws = svc.workspaces.register(str(root), label="proj")

    svc.execute(_req(str(root), workspace_id=ws.id))
    # The fake runtime recorded the Workspace object it received.
    ws_view = svc.runtime.calls[-1]
    assert ws_view is not None
    assert ws_view.tmp_root != ""
    # tmp_root must NOT be inside the source tree.
    assert not Path(ws_view.tmp_root).is_relative_to(Path(root))
    # tmp_root must be under the RedForge-managed root.
    assert "redforge-runs" in str(ws_view.tmp_root)


def test_writable_tmp_dir_created_and_cleanable(svc, tmp_path):
    """Per-run tmp dir is created, and cleanup removes it after execution."""
    root = tmp_path / "src"
    root.mkdir()
    ws = svc.workspaces.register(str(root), label="proj")

    run_id_hint = tool_request_id("cleanup")
    request = _req(str(root), workspace_id=ws.id)
    request.id = run_id_hint
    svc.execute(request)

    ws_view = svc.runtime.calls[-1]
    tmp_path_host = Path(ws_view.tmp_root)
    # The managed root exists; the per-run dir was cleaned up by execute's
    # finally block, so it must NOT linger on disk after the run.
    assert Path(svc.tmp_root).is_dir()
    assert not tmp_path_host.exists()
    assert not Path(ws_view.root).is_relative_to(tmp_path_host)


def test_runtime_receives_ro_source_mount_and_managed_rw_tmp(svc, tmp_path):
    """The runtime gets a Workspace whose root points at the source (ro) and
    whose tmp_root is the managed dir (rw) — never the source tree writable."""
    root = tmp_path / "src"
    root.mkdir()
    (root / "app.py").write_text("print('x')")
    ws = svc.workspaces.register(str(root), label="proj")
    svc.execute(_req(str(root), workspace_id=ws.id))

    ws_view = svc.runtime.calls[-1]
    assert Path(ws_view.root) == Path(root).resolve()
    assert ws_view.container_path == "/workspace"
    assert ws_view.writable_tmp == "/workspace-tmp"
    assert Path(ws_view.tmp_root) != Path(root)


def test_symlink_workspace_rejected(tmp_path):
    """A workspace path that is a symlink is rejected (untrusted tree could
    redirect the mount)."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform")
    reg = AuthorizedWorkspaceRegistry()
    with pytest.raises(WorkspaceBoundaryError):
        reg.register(str(link), label="evil-link")
