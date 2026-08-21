"""Authorized workspace registry — the security boundary for host paths.

THREAT MODEL
------------
An agent (or a compromised agent loop) must never be able to select an
arbitrary host filesystem path to mount into a container. Without this
boundary, a malicious ToolRequest could set ``target.value`` to ``~/.ssh``,
``/etc``, or an unrelated project and exfiltrate it through a tool.

AUTHORIZED FLOW
---------------
    User / Trusted Target
        -> AuthorizeWorkspaceRegistry.register(root, label)   [trusted side]
        -> returns workspace_id (opaque)
    Agent sees ONLY: workspace_id + container path (/workspace)
        -> ToolRequest(workspace_id=..., path=...)
        -> ExecutionService resolves workspace_id -> host root
        -> Runtime mounts root:/workspace:ro

The agent can never invent the host path. It can only reference a
workspace_id that a trusted caller (the orchestrator / user / policy
authorizer) registered.

Security properties:
- workspace_id is an opaque handle; the host root is never derived from
  agent input.
- Paths are normalized (resolve) and must stay inside the authorized base.
- Symlink/reparse-point escape is rejected (realpath must stay in base).
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path

from ..ids import workspace_id


class WorkspaceAuthorizationError(ValueError):
    """Raised when a workspace reference is unknown or unauthorized."""


class WorkspaceBoundaryError(ValueError):
    """Raised when a path would escape the authorized boundary."""


@dataclass(frozen=True)
class AuthorizedWorkspace:
    """A registered, authorized workspace.

    ``id`` is the opaque handle agents reference. ``root`` is the resolved
    absolute host path. ``container_path`` is where the root is mounted inside
    containers (default ``/workspace``). ``writable_tmp`` is the in-container
    path of the RedForge-managed per-run temp dir.
    """
    id: str
    root: str
    container_path: str = "/workspace"
    writable_tmp: str = "/workspace-tmp"

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "root": self.root,
            "container_path": self.container_path,
            "writable_tmp": self.writable_tmp,
        }


class AuthorizedWorkspaceRegistry:
    """Trusted registry of authorized workspaces.

    Only this class (driven by the orchestrator/user/policy) can map a
    workspace_id to a host path. The execution service resolves ids through
    this registry and rejects unknown ids.
    """

    def __init__(self, allowed_base: str | None = None) -> None:
        # If set, every registered root must live under this base (defense in
        # depth — e.g. the user's authorized projects directory).
        self.allowed_base = str(Path(allowed_base).expanduser().resolve()) if allowed_base else None
        self._workspaces: dict[str, AuthorizedWorkspace] = {}
        self._lock = threading.Lock()

    def register(self, root: str, label: str = "workspace") -> AuthorizedWorkspace:
        """Register an authorized host directory. Returns an AuthorizedWorkspace.

        Raises WorkspaceBoundaryError if the path is not a directory or escapes
        the allowed base. The generated id is opaque (never the path).
        """
        resolved = self._validate_and_resolve(root)
        wid = workspace_id(label)
        ws = AuthorizedWorkspace(id=wid, root=resolved)
        with self._lock:
            self._workspaces[wid] = ws
        return ws

    def resolve(self, workspace_id_value: str) -> AuthorizedWorkspace:
        """Resolve an opaque id to its AuthorizedWorkspace.

        Raises WorkspaceAuthorizationError for unknown ids — the agent cannot
        reference a host path that was never registered.
        """
        with self._lock:
            ws = self._workspaces.get(workspace_id_value)
        if ws is None:
            raise WorkspaceAuthorizationError(
                f"unknown workspace_id: {workspace_id_value!r} (not authorized)"
            )
        return ws

    def revoke(self, workspace_id_value: str) -> None:
        with self._lock:
            self._workspaces.pop(workspace_id_value, None)

    def list_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._workspaces)

    def _validate_and_resolve(self, root: str) -> str:
        """Resolve + verify the path is a real directory inside the boundary."""
        if not root:
            raise WorkspaceBoundaryError("workspace root is empty")
        try:
            # resolve(strict=True) follows symlinks: a symlink pointing outside
            # the base resolves to the real path, which we then check.
            resolved = Path(root).expanduser().resolve(strict=True)
        except OSError as exc:
            raise WorkspaceBoundaryError(f"workspace path does not exist: {root}") from exc
        if not resolved.is_dir():
            raise WorkspaceBoundaryError(f"workspace path is not a directory: {resolved}")
        # Reject obvious reparse points / symlinks in the *input* before
        # resolution too — defense in depth (Windows junctions, .ssh, etc.).
        if self._is_restricted(root, resolved):
            raise WorkspaceBoundaryError(f"workspace path is restricted: {root}")
        if self.allowed_base:
            try:
                resolved.relative_to(Path(self.allowed_base))
            except ValueError as exc:
                raise WorkspaceBoundaryError(
                    f"workspace {resolved} escapes allowed base {self.allowed_base}"
                ) from exc
        return str(resolved)

    @staticmethod
    def _is_restricted(raw: str, resolved: Path) -> bool:
        """Reject sensitive/system paths even if they exist (defense in depth)."""
        lower = str(resolved).lower()
        restricted_markers = (
            os.sep + ".ssh",
            os.sep + ".gnupg",
            os.sep + "windows",
            os.sep + "etc" + os.sep,
            os.sep + "usr" + os.sep,
            os.sep + "proc",
            os.sep + "sys",
            os.sep + "boot",
            os.sep + "root" + os.sep,
        )
        if any(m in lower for m in restricted_markers):
            return True
        # Symlink check: if the raw path is a symlink/reparse point, reject —
        # an untrusted tree could redirect the mount.
        try:
            if Path(raw).expanduser().is_symlink():
                return True
        except OSError:
            return True
        return False


@dataclass(frozen=True)
class Workspace:
    """An authorized local source workspace (runtime view).

    ``root`` is the normalized absolute host path of the source tree.
    ``container_path`` is where it is mounted (default ``/workspace``).
    ``writable_tmp`` is the in-container path of the writable temp dir
    (default ``/workspace-tmp``). ``tmp_root`` is the HOST path of the
    RedForge-managed per-run temp dir — always OUTSIDE the source tree
    (never ``<source>/.redforge-tmp``).
    """
    root: str
    container_path: str = "/workspace"
    writable_tmp: str = "/workspace-tmp"
    tmp_root: str = ""

    @property
    def display(self) -> str:
        return self.root

    def to_dict(self) -> dict[str, str]:
        return {
            "root": self.root,
            "container_path": self.container_path,
            "writable_tmp": self.writable_tmp,
            "tmp_root": self.tmp_root,
        }


def make_workspace(root: str, container_path: str = "/workspace", writable_tmp: str = "/workspace-tmp") -> Workspace:
    """Create a Workspace from a validated host path (no boundary checks — use
    AuthorizedWorkspaceRegistry for authorization)."""
    return Workspace(root=str(Path(root).expanduser().resolve()), container_path=container_path,
                     writable_tmp=writable_tmp)
