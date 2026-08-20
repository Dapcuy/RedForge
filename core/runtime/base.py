"""Runtime Interface contract + Docker backend (hardened).

The runtime layer exposes a minimal, stable surface. Agents never reach this
layer directly — the Tool Execution Service is the only caller.

    run(tool, target, ctx, limits) -> RunResult
    stop(run_id)
    logs(run_id)
    inspect(run_id)

The interface stays backend-agnostic (Podman can implement it later without
touching skills, agents, tools, or orchestration).
"""
from __future__ import annotations

import abc
import subprocess
from collections.abc import Iterator

from ..execution.models import ResourceLimits, utcnow_iso
from ..models import RunContext, RunResult, RunStatus, Target, Tool


class RunError(Exception):
    """Raised when a runtime cannot execute a tool."""


class Runtime(abc.ABC):
    """Abstract execution backend. ``run`` accepts resource limits."""

    name: str = "abstract"

    @abc.abstractmethod
    def run(
        self,
        tool: Tool,
        target: Target,
        ctx: RunContext,
        limits: ResourceLimits | None = None,
    ) -> RunResult:
        """Execute a tool against a target and return a normalized result."""

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
    ) -> list[str]:
        """Build the command that ``run`` would execute, without running it.

        Used for ToolRun provenance (recording the exact command/arguments).
        """


class DockerRuntime(Runtime):
    """Runs tools inside per-domain Docker images with hard resource limits.

    Uses the ``docker`` CLI (present on Windows/Linux/macOS). Limits are
    applied via docker flags: --cpus, --memory, --pids-limit, --read-only,
    --network, and --rm (filesystem is ephemeral).
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

    def _limit_flags(self, limits: ResourceLimits) -> list[str]:
        flags = [
            "--cpus", str(limits.cpu),
            "--memory", f"{limits.memory_mb}m",
            "--pids-limit", str(limits.pids_limit),
            "--network", limits.network,
        ]
        if limits.read_only_fs:
            flags += ["--read-only"]
        return flags

    def _truncate(self, text: str, max_bytes: int) -> str:
        data = text.encode("utf-8")
        if len(data) <= max_bytes:
            return text
        return data[:max_bytes].decode("utf-8", errors="replace")

    def run(
        self,
        tool: Tool,
        target: Target,
        ctx: RunContext,
        limits: ResourceLimits | None = None,
    ) -> RunResult:
        limits = limits or ResourceLimits()
        self._check_daemon()
        image = tool.image or self._default_image
        started_at = utcnow_iso()
        args = [
            self._docker, "run", "--rm",
            "--name", f"redforge-{ctx.run_id}",
        ]
        args += self._limit_flags(limits)
        for key, val in ctx.env.items():
            args += ["-e", f"{key}={val}"]
        args += [image, tool.entrypoint, target.value]

        self._runs[ctx.run_id] = RunStatus.RUNNING
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=limits.timeout_s)
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
                command=args,
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

    def command_for(self, tool: Tool, target: Target, ctx: RunContext, limits: ResourceLimits | None = None) -> list[str]:
        """Build the docker command without executing (used for ToolRun.command)."""
        limits = limits or ResourceLimits()
        image = tool.image or self._default_image
        args = [self._docker, "run", "--rm", "--name", f"redforge-{ctx.run_id}"]
        args += self._limit_flags(limits)
        for key, val in ctx.env.items():
            args += ["-e", f"{key}={val}"]
        args += [image, tool.entrypoint, target.value]
        return args
