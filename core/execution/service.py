"""Tool Execution Service: the single gate for all tool execution.

The enforced flow:

    Agent -> ToolRequest -> Policy -> Tool Resolver -> Tool Executor -> Runtime

This service owns the whole chain. Agents (and everything else) submit a
``ToolRequest``; nothing else calls the Runtime directly. It also produces the
``ToolRun`` and ``Artifact`` provenance records.

Security properties:
- Workspace: ONLY an AuthorizedWorkspace (registered by a trusted caller and
  referenced by opaque ``workspace_id``) is mounted. A ToolRequest can never
  supply a host path, and unknown ids are rejected. See
  ``AuthorizedWorkspaceRegistry``.
- Temp dir: per-run writable dirs are created by RedForge under a managed
  root (``workspace.tmp_root``), NEVER inside the user-controlled source tree.
  The source tree stays read-only at /workspace.
- Concurrency: max_parallel_runs is enforced atomically via a semaphore, not
  a racy active-count check.
- Policy is checked before any runtime call.

The core stays agent- and runtime-independent: this service depends only on the
Policy engine, Tool registry, the Runtime *interface*, and the workspace
registry.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
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
from .workspace import (
    AuthorizedWorkspace,
    AuthorizedWorkspaceRegistry,
    Workspace,
    WorkspaceAuthorizationError,
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
    """Coordinates Policy -> Resolver -> Executor -> Runtime, with concurrency control."""

    def __init__(
        self,
        registry: ToolRegistry,
        runtime: Runtime,
        policy: PolicyEngine,
        workspaces: AuthorizedWorkspaceRegistry | None = None,
        max_concurrency: int | None = None,
        tmp_root: str | None = None,
    ) -> None:
        self.registry = registry
        self.runtime = runtime
        self.policy = policy
        # The ONLY way a host path becomes a workspace. If no registry is
        # injected, an empty one is created — source-dir requests without a
        # registered workspace_id are REJECTED (fail-closed).
        self.workspaces = workspaces or AuthorizedWorkspaceRegistry()
        # RedForge-managed temp root for per-run writable dirs (outside any
        # user-controlled source tree).
        self.tmp_root = tmp_root or os.path.join(tempfile.gettempdir(), "redforge-runs")
        os.makedirs(self.tmp_root, exist_ok=True)
        if max_concurrency is None:
            max_concurrency = self.policy.policy.max_parallel_runs
        self._semaphore = threading.BoundedSemaphore(max_concurrency)
        self._tmp_dirs: dict[str, str] = {}
        self._tmp_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Workspace resolution
    # ------------------------------------------------------------------
    def resolve_workspace(self, request: ToolRequest) -> AuthorizedWorkspace | None:
        """Resolve the authorized workspace for a request.

        FAIL-CLOSED:
        - A ``workspace_id`` is resolved through the registry; unknown ids are
          rejected.
        - A raw host path in ``target.value`` for SOURCE_DIR targets is only
          accepted if it was registered (legacy path) — the service never
          *derives* a mount from unregistered agent input.
        - URL targets never get a workspace.
        """
        # Explicit workspace_id is the only agent-facing mechanism.
        if request.workspace_id:
            return self.workspaces.resolve(request.workspace_id)

        # Backward-compatible path: source-dir targets may carry a registered
        # host path, but it must already be in the registry (registered by the
        # trusted caller). If the exact path was never authorized, reject.
        if request.target.kind == TargetKind.SOURCE_DIR and request.target.value:
            root = str(Path(request.target.value).expanduser().resolve())
            for wid in self.workspaces.list_ids():
                ws = self.workspaces.resolve(wid)
                if os.path.normcase(os.path.abspath(ws.root)) == os.path.normcase(os.path.abspath(root)):
                    return ws
            raise WorkspaceAuthorizationError(
                f"target path is not an authorized workspace: {request.target.value!r}"
            )
        return None

    def _make_per_run_tmp(self, wid: str, run_id: str) -> str:
        """Create a RedForge-managed per-run writable dir OUTSIDE the source tree."""
        run_tmp = os.path.join(self.tmp_root, f"{wid}-{run_id}")
        os.makedirs(run_tmp, exist_ok=True)
        with self._tmp_lock:
            self._tmp_dirs[run_id] = run_tmp
        return run_tmp

    def cleanup_run_tmp(self, run_id: str) -> None:
        with self._tmp_lock:
            d = self._tmp_dirs.pop(run_id, None)
        if d and os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)

    # ------------------------------------------------------------------
    # Argument remapping
    # ------------------------------------------------------------------
    def _remap_workspace_paths(
        self,
        request: ToolRequest,
        workspace: Workspace | None,
    ) -> ToolRequest:
        """Rewrite workspace-relative file arguments to container paths.

        ``path`` and ``config`` are mapped under the container workspace path.
        Anything else is untouched. Host paths are never emitted.
        """
        if workspace is None:
            return request
        args = dict(request.arguments)
        for key in ("path", "config"):
            if args.get(key) and not str(args[key]).startswith(workspace.container_path):
                rel = str(args[key]).lstrip("./")
                args[key] = f"{workspace.container_path}/{rel}"
        request.arguments = args
        return request

    def _resolve_tool(self, request: ToolRequest):
        if request.tool_name:
            tool = self.registry.get(request.tool_name)
            if tool is None:
                raise KeyError(f"unknown tool: {request.tool_name}")
        else:
            tool = self.registry.resolve_capability(request.capability)
        return tool

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

    def _stage_file_inputs(self, request: ToolRequest, run_tmp: str) -> ToolRequest:
        """Copy tool file inputs (template/wordlist) into the per-run tmp dir.

        URL tools (nuclei templates, ffuf wordlists) reference local files.
        We copy those into the RedForge-managed per-run tmp dir (mounted at
        /workspace-tmp) so the container can read them. The argument path is
        remapped to the container path. Only whitelisted file args are staged;
        everything else is passed as a flag untouched.
        """
        args = dict(request.arguments)
        for key in ("template", "wordlist"):
            if not args.get(key):
                continue
            host_path = str(args[key])
            # Skip already-container paths.
            if host_path.startswith(("/workspace", "/tmp")):
                continue
            if not os.path.isfile(host_path):
                raise ValueError(f"tool input file not found: {host_path!r}")
            fname = os.path.basename(host_path)
            dest = os.path.join(run_tmp, fname)
            shutil.copyfile(host_path, dest)
            args[key] = f"/workspace-tmp/{fname}"
        request.arguments = args
        return request

    def execute(self, request: ToolRequest) -> ExecutionOutcome:
        """Execute a ToolRequest end-to-end under the concurrency semaphore.

        Returns an ExecutionOutcome (ToolRun + artifacts). Raises
        ``WorkspaceAuthorizationError`` (unknown workspace), ``PolicyViolation``
        (from the policy engine), ``RunError`` (from the runtime), or
        ``ValueError`` (bad tool arguments) on failure.
        """
        # 1. Resolve capability -> tool (before policy, so policy sees tool name).
        tool = self._resolve_tool(request)

        # 1b. Validate arguments against the tool's input schema (if any).
        self.registry.validate_arguments(tool, request.arguments)

        # 2. Resolve the AUTHORIZED workspace (never agent-derived host mounts).
        aws = self.resolve_workspace(request)

        # 3. Policy gate (returns effective limits); runs under the semaphore.
        with self._semaphore:
            limits = self.policy.check_request(request, tool.name)
            self.policy.check_privileged(tool.image)

            run_id = tool_run_id(request.context.scan_id, request.id)
            # Env var whitelist: only vars explicitly allowed by policy OR the
            # tool manifest reach the container. Anything else is dropped so an
            # agent/Hermes cannot smuggle DOCKER_HOST, HTTP_PROXY, etc.
            requested_env = dict(request.arguments.get("env", {}) or {})
            allowed_env: set[str] = set(self.policy.policy.env_allowlist)
            allowed_env.update((tool.runtime.get("env_allowlist") or []) if tool.runtime else [])
            safe_env = {k: v for k, v in requested_env.items() if k in allowed_env}
            ctx = RunContext(run_id=run_id, timeout_s=limits.timeout_s, env=safe_env)

            # 4. Build the runtime Workspace: RedForge-managed per-run tmp dir
            #    OUTSIDE the source tree; the source tree stays read-only.
            #    URL tools also get a per-run tmp dir for file inputs
            #    (nuclei templates, ffuf wordlists), copied in below.
            run_tmp = self._make_per_run_tmp(aws.id if aws else "url", run_id)
            workspace: Workspace | None
            if aws is not None:
                workspace = Workspace(
                    root=aws.root,
                    container_path=aws.container_path,
                    writable_tmp=aws.writable_tmp,
                    tmp_root=run_tmp,   # host path of the managed per-run tmp dir
                )
            else:
                # URL tool: no source tree; only the writable tmp dir is mounted.
                workspace = Workspace(
                    root="",
                    container_path="/workspace",
                    writable_tmp="/workspace-tmp",
                    tmp_root=run_tmp,
                )
            request = self._remap_workspace_paths(request, workspace)
            request = self._stage_file_inputs(request, run_tmp)

            # Tool arguments (container-remapped paths + flags).
            tool_args: list[str] | None = None
            if aws is not None and request.arguments.get("path"):
                # Source tool: remapped path is the first argument.
                tool_args = [request.arguments["path"]]
            elif aws is None:
                # URL tool: positional URL, unless `u` overrides it.
                if "u" in request.arguments:
                    tool_args = []
                else:
                    tool_args = [request.target.value]
            if tool_args is not None:
                flag_map = tool.runtime.get("flag_map", {}) or {}
                for key, val in request.arguments.items():
                    if key in {"path", "env"}:
                        continue
                    flag = flag_map.get(key, f"--{key}")
                    if isinstance(val, list):
                        for v in val:
                            tool_args += [flag, str(v)]
                    elif isinstance(val, bool):
                        if val:
                            tool_args.append(flag)
                    else:
                        tool_args += [flag, str(val)]

            try:
                command = self.runtime.command_for(tool, request.target, ctx, limits, workspace, tool_args)
                started_at = utcnow_iso()
                result = self.runtime.run(
                    tool, request.target, ctx,
                    limits=limits, workspace=workspace, args=tool_args,
                )
            finally:
                # Always clean up the per-run temp dir, even on failure.
                self.cleanup_run_tmp(run_id)

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
