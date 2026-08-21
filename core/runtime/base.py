"""Runtime Interface contract + Docker backend (hardened, workspace-aware).

The runtime layer exposes a minimal, stable surface. Agents never reach this
layer directly — the Tool Execution Service is the only caller.

    run(tool, target, ctx, limits, workspace) -> RunResult
    stop(run_id)
    logs(run_id)
    inspect(run_id)

Workspace mounting: only the authorized Workspace (derived from the target,
never supplied by an agent) is mounted. Host mounts from ToolRequest/Agent are
impossible by construction — the workspace is the only mount.

The interface stays backend-agnostic (Podman can implement it later without
touching skills, agents, tools, or orchestration).
"""
from __future__ import annotations

import abc
import os
import subprocess
from collections.abc import Iterator

from ..execution.models import ResourceLimits, utcnow_iso
from ..execution.workspace import Workspace
from ..models import RunContext, RunResult, RunStatus, Target, Tool


class RunError(Exception):
    """Raised when a runtime cannot execute a tool."""


class Runtime(abc.ABC):
    """Abstract execution backend. ``run`` accepts resource limits + workspace."""

    name: str = "abstract"

    @abc.abstractmethod
    def run(
        self,
        tool: Tool,
        target: Target,
        ctx: RunContext,
        limits: ResourceLimits | None = None,
        workspace: Workspace | None = None,
        args: list[str] | None = None,
    ) -> RunResult:
        """Execute a tool against a target and return a normalized result.

        ``args`` (optional) are tool arguments appended after the entrypoint.
        For source tools, the execution service passes the container-remapped
        path here instead of the raw host path.
        """

    @abc.abstractmethod
    def stop(self, run_id: str) -> None:
        """Stop a running execution."""

    @abc.abstractmethod
    def logs(self, run_id: str) -> Iterator[str]:
        """Stream logs for a run."""

    @abc.abstractmethod
    def inspect(self, run_id: str) -> RunStatus:
        """Return the current status of a run."""

    @abc.abstractmethod
    def command_for(
        self,
        tool: Tool,
        target: Target,
        ctx: RunContext,
        limits: ResourceLimits | None = None,
        workspace: Workspace | None = None,
        args: list[str] | None = None,
    ) -> list[str]:
        """Build the command that ``run`` would execute, without running it.

        Used for ToolRun provenance (recording the exact command/arguments).
        """


class DockerRuntime(Runtime):
    """Runs tools inside per-domain Docker images with hard resource limits.

    - The authorized source Workspace is mounted read-only at ``/workspace``.
    - A controlled writable temp dir is mounted at ``/workspace-tmp`` so tools
      that need build/temp output (foundry, semgrep cache) can write without
      making the whole container filesystem writable.
    - No other host mounts are ever added.
    - Limits: --cpus, --memory, --pids-limit, --network, and (unless the tool
      needs writable fs) --read-only. ``--rm`` keeps the fs ephemeral.
    """

    name = "docker"

    def __init__(self, docker_bin: str = "docker", default_image: str = "redforge/base") -> None:
        self._docker = docker_bin
        self._default_image = default_image
        self._runs: dict[str, RunStatus] = {}

    def _check_daemon(self) -> None:
        proc = subprocess.run([self._docker, "info"], capture_output=True, text=True)
        if proc.returncode != 0:
            raise RunError(
                "Docker daemon is not running. Start Docker Desktop, then retry. "
                f"(docker info: {proc.stderr.strip()[:200]})"
            )

    def _limit_flags(self, limits: ResourceLimits, workspace: Workspace | None) -> list[str]:
        flags = [
            "--cpus", str(limits.cpu),
            "--memory", f"{limits.memory_mb}m",
            "--pids-limit", str(limits.pids_limit),
            "--network", limits.network,
        ]
        if limits.read_only_fs:
            flags += ["--read-only", "--tmpfs", "/tmp:rw,size=64m,exec"]
        if workspace is not None:
            # Mount the authorized source tree read-only (if present) + a
            # RedForge-managed per-run writable temp dir. The writable dir is
            # provided by the execution service via workspace.tmp_root and is
            # OUTSIDE the user-controlled source tree (never <source>/.redforge-tmp),
            # so an untrusted source tree cannot redirect or poison the mount.
            # URL tools (no source tree) still get the writable tmp dir for
            # file inputs (nuclei templates, ffuf wordlists).
            tmp_host = workspace.tmp_root or os.path.join(workspace.root, ".redforge-tmp")
            os.makedirs(tmp_host, exist_ok=True)
            # Normalize to forward slashes — Docker on Windows handles
            # `C:/...` reliably, while a backslash inside a --volume string can
            # break parsing.
            tmp_host = tmp_host.replace("\\", "/")
            source_vol = (
                f"{workspace.root.replace(chr(92), '/')}:{workspace.container_path}:ro"
                if workspace.root
                else None
            )
            if source_vol:
                flags += ["--volume", source_vol]
            flags += ["--volume", f"{tmp_host}:{workspace.writable_tmp}:rw"]
        return flags

    def _truncate(self, text: str, max_bytes: int) -> str:
        data = text.encode("utf-8")
        if len(data) <= max_bytes:
            return text
        return data[:max_bytes].decode("utf-8", errors="replace")

    def _command(
        self,
        tool: Tool,
        target: Target,
        ctx: RunContext,
        limits: ResourceLimits,
        workspace: Workspace | None,
        args: list[str] | None = None,
    ) -> list[str]:
        image = tool.image or self._default_image
        cmd = [self._docker, "run", "--rm", "--name", f"redforge-{ctx.run_id}"]
        cmd += self._limit_flags(limits, workspace)
        for key, val in ctx.env.items():
            cmd += ["-e", f"{key}={val}"]
        if workspace is not None:
            # Tools that need a writable home/cache (semgrep writes ~/.semgrep
            # and temp files) get HOME + TMPDIR redirected to the controlled
            # writable tmp dir, which is mounted rw even when the root
            # filesystem is read-only.
            cmd += [
                "-e", f"HOME={workspace.writable_tmp}",
                "-e", f"SEMGREP_HOME={workspace.writable_tmp}",
                "-e", f"TMPDIR={workspace.writable_tmp}",
            ]
        cmd += [image, tool.entrypoint]
        # Tool arguments: explicit args win over the raw target value.
        if args:
            cmd += args
        else:
            cmd += [target.value]
        return cmd

    def run(
        self,
        tool: Tool,
        target: Target,
        ctx: RunContext,
        limits: ResourceLimits | None = None,
        workspace: Workspace | None = None,
        args: list[str] | None = None,
    ) -> RunResult:
        limits = limits or ResourceLimits()
        self._check_daemon()
        started_at = utcnow_iso()
        full_cmd = self._command(tool, target, ctx, limits, workspace, args)

        self._runs[ctx.run_id] = RunStatus.RUNNING
        try:
            proc = subprocess.run(full_cmd, capture_output=True, text=True, timeout=limits.timeout_s)
            status = RunStatus.SUCCESS if proc.returncode == 0 else RunStatus.FAILED
            self._runs[ctx.run_id] = status
            return RunResult(
                run_id=ctx.run_id,
                tool=tool.name,
                status=status,
                exit_code=proc.returncode,
                stdout=self._truncate(proc.stdout, limits.max_output_bytes),
                stderr=self._truncate(proc.stderr, limits.max_output_bytes),
                tool_version=str(tool.runtime.get("version", "")),
                command=full_cmd,
                started_at=started_at,
                finished_at=utcnow_iso(),
            )
        except subprocess.TimeoutExpired as exc:
            self._runs[ctx.run_id] = RunStatus.TIMEOUT
            raise RunError(f"tool {tool.name} timed out after {limits.timeout_s}s") from exc

    def stop(self, run_id: str) -> None:
        subprocess.run([self._docker, "stop", f"redforge-{run_id}"], capture_output=True)

    def logs(self, run_id: str) -> Iterator[str]:
        proc = subprocess.run([self._docker, "logs", f"redforge-{run_id}"], capture_output=True, text=True)
        yield proc.stdout

    def inspect(self, run_id: str) -> RunStatus:
        return self._runs.get(run_id, RunStatus.PENDING)

    def container_name(self, run_id: str) -> str:
        return f"redforge-{run_id}"

    def command_for(
        self,
        tool: Tool,
        target: Target,
        ctx: RunContext,
        limits: ResourceLimits | None = None,
        workspace: Workspace | None = None,
        args: list[str] | None = None,
    ) -> list[str]:
        """Build the docker command without executing (used for ToolRun.command)."""
        limits = limits or ResourceLimits()
        return self._command(tool, target, ctx, limits, workspace, args)
