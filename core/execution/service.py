"""Tool Execution Service: the single gate for all tool execution.

The enforced flow:

    Agent -> ToolRequest -> Policy -> Tool Resolver -> Tool Executor -> Runtime

This service owns the whole chain. Agents (and everything else) submit a
``ToolRequest``; nothing else calls the Runtime directly. It also produces the
``ToolRun`` and ``Artifact`` provenance records.

The core stays agent- and runtime-independent: this service depends only on the
Policy engine, Tool registry, and the Runtime *interface*.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..ids import artifact_id, tool_run_id
from ..models import RunContext, RunResult
from ..policy.engine import PolicyEngine
from ..runtime.base import Runtime
from ..tools.registry import ToolRegistry
from .models import (
    Artifact,
    ToolRequest,
    ToolRun,
    utcnow_iso,
)


@dataclass
class ExecutionOutcome:
    """The full result of executing a ToolRequest: a ToolRun + its artifacts."""
    tool_run: ToolRun
    artifacts: list[Artifact] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_run": self.tool_run.to_dict(),
            "artifacts": [a.to_dict() for a in self.artifacts],
        }


class ToolExecutionService:
    """Coordinates Policy -> Resolver -> Executor -> Runtime."""

    def __init__(
        self,
        registry: ToolRegistry,
        runtime: Runtime,
        policy: PolicyEngine,
    ) -> None:
        self.registry = registry
        self.runtime = runtime
        self.policy = policy

    def _build_artifacts(self, run: ToolRun, result: RunResult) -> list[Artifact]:
        artifacts: list[Artifact] = []
        if result.stdout:
            artifacts.append(Artifact(
                id=artifact_id(run.id, "stdout"),
                tool_run_id=run.id,
                kind="stdout",
                format="text",
                content=result.stdout,
                size_bytes=len(result.stdout.encode("utf-8")),
            ))
        if result.stderr:
            artifacts.append(Artifact(
                id=artifact_id(run.id, "stderr"),
                tool_run_id=run.id,
                kind="stderr",
                format="text",
                content=result.stderr,
                size_bytes=len(result.stderr.encode("utf-8")),
            ))
        return artifacts

    def execute(self, request: ToolRequest) -> ExecutionOutcome:
        """Execute a ToolRequest end-to-end.

        Returns an ExecutionOutcome (ToolRun + artifacts). Raises
        ``PolicyViolation`` (from the policy engine) or ``RunError`` (from the
        runtime) on failure.
        """
        # 1. Resolve capability -> tool (before policy, so policy sees tool name).
        if request.tool_name:
            tool = self.registry.get(request.tool_name)
            if tool is None:
                raise KeyError(f"unknown tool: {request.tool_name}")
        else:
            tool = self.registry.resolve_capability(request.capability)

        # 2. Policy gate (returns effective limits).
        limits = self.policy.check_request(request, tool.name)
        self.policy.check_privileged(tool.image)

        # 3. Build the run context and execute through the runtime interface.
        run_id = tool_run_id(request.context.scan_id, request.id)
        ctx = RunContext(run_id=run_id, timeout_s=limits.timeout_s, env=request.arguments.get("env", {}))

        command = self.runtime.command_for(tool, request.target, ctx, limits)
        started_at = utcnow_iso()
        result = self.runtime.run(tool, request.target, ctx, limits=limits)

        # 4. Wrap the result in provenance-aware ToolRun + Artifacts.
        run = ToolRun(
            id=run_id,
            tool_name=tool.name,
            tool_version=str(tool.runtime.get("version", "")),
            capability=request.capability or (tool.capabilities[0] if tool.capabilities else ""),
            target=request.target.value,
            context=request.context,
            command=command,
            runtime=self.runtime.name,
            status=result.status,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            timeout_s=limits.timeout_s,
            started_at=started_at,
            finished_at=result.finished_at or utcnow_iso(),
            limits=limits,
        )
        artifacts = self._build_artifacts(run, result)
        run.artifact_ids = [a.id for a in artifacts]
        return ExecutionOutcome(tool_run=run, artifacts=artifacts)
