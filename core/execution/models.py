"""Execution models: ExecutionContext, ResourceLimits, ToolRequest, ToolRun, Artifact.

These are the contracts of the execution architecture:

    Agent -> ToolRequest -> Policy -> Tool Resolver -> Tool Executor -> Runtime

Agents produce a ``ToolRequest`` (intent). They never touch the runtime.
The Tool Executor resolves the tool, applies resource limits, invokes the
Runtime, and returns a ``ToolRun`` whose raw output is captured as ``Artifact``.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ..models import RunStatus, Target

if TYPE_CHECKING:  # pragma: no cover
    from .workspace import Workspace


def utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class ExecutionContext:
    """Correlation context that flows through every stage of a run.

    Carries the stable parent IDs so any artifact/evidence/finding can be
    traced back to the project, target, scan, task, and agent run that
    produced it. It is agent- and runtime-independent.
    """
    project_id: str
    target_id: str
    scan_id: str
    task_id: str = ""
    agent_run_id: str = ""
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ResourceLimits:
    """Hard resource limits applied to every tool execution.

    Defaults are deliberately conservative. The Policy engine is the authority
    that produces effective limits for a given tool/request.
    """
    timeout_s: int = 300
    cpu: float = 1.0            # docker --cpus
    memory_mb: int = 512        # docker --memory (MB)
    pids_limit: int = 256       # docker --pids-limit
    read_only_fs: bool = True   # docker --read-only
    network: str = "none"       # none | bridge | host
    max_output_bytes: int = 10_000_000

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ResourceLimits:
        data = data or {}
        return cls(
            timeout_s=int(data.get("timeout_s", 300)),
            cpu=float(data.get("cpu", 1.0)),
            memory_mb=int(data.get("memory_mb", 512)),
            pids_limit=int(data.get("pids_limit", 256)),
            read_only_fs=bool(data.get("read_only_fs", True)),
            network=str(data.get("network", "none")),
            max_output_bytes=int(data.get("max_output_bytes", 10_000_000)),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolRequest:
    """An agent's request to run a capability/tool. The ONLY way tools execute.

    Fields:
        capability: abstract capability (resolved to a concrete tool later).
        tool_name:  optional preferred tool name (empty = resolver default).
        target:     what to run against.
        context:    correlation context (project/target/scan/...).
        workspace:  optional authorized Workspace for source targets. NEVER
                    supplied by the agent; derived from the target by the
                    orchestrator and validated by the execution service.
        arguments:  tool-specific arguments (validated against input schema).
        source:     which agent requested this (provenance).
        limits:     optional per-request limits; if unset, policy defaults apply.
    """
    id: str
    capability: str
    target: Target
    context: ExecutionContext
    tool_name: str = ""
    workspace: Workspace | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    limits: ResourceLimits | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["context"] = self.context.to_dict()
        d["workspace"] = self.workspace.to_dict() if self.workspace else None
        d["limits"] = self.limits.to_dict() if self.limits else None
        return d


@dataclass
class ToolRun:
    """The full record of a single tool execution.

    Captures everything needed for provenance: command/arguments, runtime,
    exit code, stdout/stderr, status, timestamps, timeout, and tool version.
    """
    id: str
    tool_name: str
    tool_version: str
    capability: str
    target: str
    context: ExecutionContext
    command: list[str]
    runtime: str
    status: RunStatus
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    timeout_s: int = 300
    started_at: str = ""
    finished_at: str = ""
    artifact_ids: list[str] = field(default_factory=list)
    limits: ResourceLimits = field(default_factory=ResourceLimits)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["context"] = self.context.to_dict()
        d["limits"] = self.limits.to_dict()
        return d


@dataclass
class Artifact:
    """A raw output produced by a tool run.

    ``content`` holds small inline payloads; ``path`` references a large blob
    stored outside the database (content-addressed by sha256). Exactly one of
    ``content``/``path`` is authoritative for large artifacts.
    """
    id: str
    tool_run_id: str
    kind: str            # stdout | stderr | http-response | source-snippet | trace | fuzz-result | file
    format: str          # text | json | bytes
    content: str = ""    # inline payload (small artifacts)
    path: str = ""       # blob path (large artifacts)
    sha256: str = ""
    size_bytes: int = 0
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
