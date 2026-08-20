"""Workspace abstraction for local source targets.

A Workspace is the *authorized* local source tree that tools may access.
Security rules:

- The ToolRequest/Agent NEVER supplies host mounts. Only the Workspace (derived
  from the Target by the orchestrator, validated by the execution service)
  determines what is mounted into a container.
- Workspace paths are validated and normalized (resolved, must exist, must be
  inside the allowed base).
- Docker mounts the workspace read-only at ``/workspace`` and provides a
  controlled writable temp dir at ``/workspace-tmp``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class WorkspaceError(ValueError):
    """Raised when a workspace path is invalid or unauthorized."""


@dataclass(frozen=True)
class Workspace:
    """An authorized local source workspace.

    ``root`` is the normalized absolute host path of the source tree.
    ``container_path`` is where it is mounted (default ``/workspace``).
    ``writable_tmp`` is a controlled writable location for tools that need
    temporary/build output (default ``/workspace-tmp``).
    """
    root: str
    container_path: str = "/workspace"
    writable_tmp: str = "/workspace-tmp"

    @property
    def display(self) -> str:
        return self.root

    def to_dict(self) -> dict[str, str]:
        return {
            "root": self.root,
            "container_path": self.container_path,
            "writable_tmp": self.writable_tmp,
        }


def validate_workspace_path(path: str | os.PathLike[str], base: str | None = None) -> str:
    """Validate and normalize a workspace path.

    Returns the resolved absolute path. Raises WorkspaceError if:
      - the path is empty
      - the resolved path does not exist or is not a directory
      - ``base`` is given and the resolved path escapes it
    """
    if not path:
        raise WorkspaceError("workspace path is empty")
    try:
        resolved = Path(path).expanduser().resolve(strict=True)
    except OSError as exc:
        raise WorkspaceError(f"workspace path does not exist: {path}") from exc

    if not resolved.is_dir():
        raise WorkspaceError(f"workspace path is not a directory: {resolved}")

    if base:
        base_resolved = Path(base).expanduser().resolve(strict=True)
        try:
            resolved.relative_to(base_resolved)
        except ValueError as exc:
            raise WorkspaceError(
                f"workspace path {resolved} escapes allowed base {base_resolved}"
            ) from exc

    return str(resolved)


def make_workspace(root: str, container_path: str = "/workspace", writable_tmp: str = "/workspace-tmp") -> Workspace:
    """Create a validated Workspace from a host path."""
    validated = validate_workspace_path(root)
    return Workspace(root=validated, container_path=container_path, writable_tmp=writable_tmp)
