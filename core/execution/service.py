"""Tool Execution Service: the single gate for all tool execution.

The enforced flow:

    Agent -> ToolRequest -> Policy -> Tool Resolver -> Tool Executor -> Runtime

This service owns the whole chain. Agents (and everything else) submit a
``ToolRequest``; nothing else calls the Runtime directly. It also produces the
``ToolRun`` and ``Artifact`` provenance records.

Security properties:
- Workspace: only the authorized Workspace (validated here) is mounted.
  A ToolRequest can never add host mounts.
- Concurrency: max_parallel_runs is enforced atomically via a semaphore, not
  a racy active-count check.
- Policy is checked before any runtime call.

The core stays agent- and runtime-independent: this service depends only on the
Policy engine, Tool registry, and the Runtime *interface*.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from ..ids import artifact_id, tool_run_id
from ..models import RunContext, RunResult, TargetKind
from ..policy.engine import PolicyEngine
from ..runtime.base import Runtime
from ..tools.registry import ToolRegistry
from .models import (
    Artifact,
    ToolRequest,
    ToolRun,
    utcnow_iso,
)
from .workspace import make_workspace, validate_workspace_path


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
    """Coordinates Policy -> Resolver -> Executor -> Runtime, with concurrency control."""

    def __init__(
        self,
        registry: ToolRegistry,
        runtime: Runtime,
        policy: PolicyEngine,
        max_concurrency: int | None = None,
    ) -> None:
        self.registry = registry
        self.runtime = runtime
        self.policy = policy
        # Concurrency limit from policy (or explicit override). Uses a semaphore
        # so the limit is atomic across threads — no racy active-count check.
        if max_concurrency is None:
            max_concurrency = self.policy.policy.max_parallel_runs
        self._semaphore = threading.BoundedSemaphore(max_concurrency)

    def _resolve_tool(self, request: ToolRequest):
        if request.tool_name:
            tool = self.registry.get(request.tool_name)
            if tool is None:
                raise KeyError(f"unknown tool: {request.tool_name}")
        else:
            tool = self.registry.resolve_capability(request.capability)
        return tool

    def _validate_workspace(self, request: ToolRequest):
        """Derive and validate the workspace for source targets.

        The agent/request NEVER supplies host mounts. For a source-dir target,
        we require the target.value to be a valid workspace path. For a URL
        target, no workspace is mounted (network-only tools).
        """
        if request.workspace is not None:
            # A caller-supplied workspace must still pass validation.
            validate_workspace_path(request.workspace.root)
            return request.workspace

        if request.target.kind == TargetKind.SOURCE_DIR and request.target.value:
            root = validate_workspace_path(request.target.value)
            return make_workspace(root)

        return None

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

    def _remap_workspace_paths(
        self,
        request: ToolRequest,
        workspace,
    ) -> ToolRequest:
        """Rewrite arguments.path to the container workspace path.

        Tools that consume a file inside the source tree (semgrep, slither,
        foundry, e2e-probe) receive a path relative to the workspace. Because
        the workspace is mounted at ``container_path``, the argument must point
        there, not at the host path. We only rewrite the ``path`` argument when
        a workspace is present; all other arguments are untouched.
        """
        if workspace is None:
            return request
        args = dict(request.arguments)
        # Rewrite workspace-relative file arguments to container paths.
        for key in ("path", "config"):
            if args.get(key) and not str(args[key]).startswith(workspace.container_path):
                rel = str(args[key]).lstrip("./")
                args[key] = f"{workspace.container_path}/{rel}"
        request.arguments = args
        return request

    def execute(self, request: ToolRequest) -> ExecutionOutcome:
        """Execute a ToolRequest end-to-end under the concurrency semaphore.

        Returns an ExecutionOutcome (ToolRun + artifacts). Raises
        ``PolicyViolation`` (from the policy engine), ``RunError`` (from the
        runtime), or ``ValueError`` (bad tool arguments) on failure.
        """
        # 1. Resolve capability -> tool (before policy, so policy sees tool name).
        tool = self._resolve_tool(request)

        # 1b. Validate arguments against the tool's input schema (if any).
        self.registry.validate_arguments(tool, request.arguments)

        # 2. Validate workspace (before policy: policy may scope by workspace).
        workspace = self._validate_workspace(request)
        request = self._remap_workspace_paths(request, workspace)

        # 3. Policy gate (returns effective limits); runs under the semaphore.
        with self._semaphore:
            limits = self.policy.check_request(request, tool.name)
            self.policy.check_privileged(tool.image)

            # 4. Build the run context and execute through the runtime interface.
            run_id = tool_run_id(request.context.scan_id, request.id)
            ctx = RunContext(run_id=run_id, timeout_s=limits.timeout_s, env=request.arguments.get("env", {}))

            # Tool arguments: for source tools, the (container-remapped) path is
            # passed explicitly, followed by any additional tool arguments
            # (e.g. --json for semgrep). Without a workspace, the raw target
            # value is used by the runtime.
            tool_args: list[str] | None = None
            if workspace is not None and request.arguments.get("path"):
                tool_args = [request.arguments["path"]]
                for key, val in request.arguments.items():
                    if key in {"path", "env"}:
                        continue
                    if isinstance(val, list):
                        tool_args.extend(str(v) for v in val)
                    elif isinstance(val, bool):
                        if val:
                            tool_args.append(f"--{key}")
                    else:
                        tool_args.append(f"--{key}={val}")
            elif workspace is None and request.arguments.get("flags"):
                # Non-workspace tools may still receive explicit flags.
                tool_args = list(request.arguments["flags"])

            command = self.runtime.command_for(tool, request.target, ctx, limits, workspace, tool_args)
            started_at = utcnow_iso()
            result = self.runtime.run(
                tool, request.target, ctx,
                limits=limits, workspace=workspace, args=tool_args,
            )

            # 5. Wrap the result in provenance-aware ToolRun + Artifacts.
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
