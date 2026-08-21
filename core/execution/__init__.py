"""Execution layer: the ToolRequest -> ... -> Runtime pipeline.

``models`` are imported eagerly (they are dependency-free). ``service`` is
lazy-loaded to avoid a circular import: ``runtime.base`` imports
``execution.models``, while ``service`` imports ``runtime.base``.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .models import (
    Artifact,
    ExecutionContext,
    ResourceLimits,
    ToolRequest,
    ToolRun,
    utcnow_iso,
)
from .workspace import (
    AuthorizedWorkspace,
    AuthorizedWorkspaceRegistry,
    Workspace,
    WorkspaceAuthorizationError,
    WorkspaceBoundaryError,
    make_workspace,
)

if TYPE_CHECKING:  # pragma: no cover
    from .service import ToolExecutionService

__all__ = [
    "Artifact",
    "AuthorizedWorkspace",
    "AuthorizedWorkspaceRegistry",
    "ExecutionContext",
    "ResourceLimits",
    "ToolExecutionService",
    "ToolRequest",
    "ToolRun",
    "Workspace",
    "WorkspaceAuthorizationError",
    "WorkspaceBoundaryError",
    "make_workspace",
    "utcnow_iso",
]


def __getattr__(name: str):
    if name == "ToolExecutionService":
        from .service import ToolExecutionService

        return ToolExecutionService
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")