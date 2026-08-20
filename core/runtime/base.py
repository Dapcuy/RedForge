"""Runtime Interface contract and the Tool Executor.

The runtime layer exposes a minimal, stable surface:

    run(tool, target, ctx) -> RunResult
    stop(run_id)
    logs(run_id)
    inspect(run_id)

Skills never know *where* a tool runs (Docker now, Podman later); they only
request a capability, which the Tool Registry resolves to a tool, which the
Runtime executes.
"""
from __future__ import annotations

import abc
import subprocess
from typing import Iterator

from ..models import RunContext, RunResult, RunStatus, Target, Tool


class RunError(Exception):
    """Raised when a runtime cannot execute a tool."""


class Runtime(abc.ABC):
    """Abstract execution backend."""

    @abc.abstractmethod
    def run(self, tool: Tool, target: Target, ctx: RunContext) -> RunResult:
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


class DockerRuntime(Runtime):
    """Runs tools inside per-domain Docker images.

    Uses the ``docker`` CLI (present on Windows/Linux/macOS) rather than
    docker-py, so the only requirement is a working ``docker`` binary and a
    running daemon.
    """

    name = "docker"

    def __init__(self, docker_bin: str = "docker", default_image: str = "redforge/base") -> None:
        self._docker = docker_bin
        self._default_image = default_image
        self._runs: dict[str, RunStatus] = {}

    def _check_daemon(self) -> None:
        proc = subprocess.run(
            [self._docker, "info"],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RunError(
                "Docker daemon is not running. Start Docker Desktop, then retry. "
                f"(docker info: {proc.stderr.strip()[:200]})"
            )

    def run(self, tool: Tool, target: Target, ctx: RunContext) -> RunResult:
        self._check_daemon()
        image = tool.image or self._default_image
        args = [
            self._docker, "run", "--rm",
            "--name", f"redforge-{ctx.run_id}",
            "--network", "host" if target.kind.value == "url" else "none",
        ]
        for key, val in ctx.env.items():
            args += ["-e", f"{key}={val}"]

        args += [image, tool.entrypoint, target.value]
        self._runs[ctx.run_id] = RunStatus.RUNNING
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=ctx.timeout_s)
            status = RunStatus.SUCCESS if proc.returncode == 0 else RunStatus.FAILED
            self._runs[ctx.run_id] = status
            return RunResult(
                run_id=ctx.run_id,
                tool=tool.name,
                status=status,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
            )
        except subprocess.TimeoutExpired as exc:
            self._runs[ctx.run_id] = RunStatus.TIMEOUT
            raise RunError(f"tool {tool.name} timed out after {ctx.timeout_s}s") from exc

    def stop(self, run_id: str) -> None:
        subprocess.run([self._docker, "stop", f"redforge-{run_id}"], capture_output=True)

    def logs(self, run_id: str) -> Iterator[str]:
        proc = subprocess.run(
            [self._docker, "logs", f"redforge-{run_id}"],
            capture_output=True,
            text=True,
        )
        yield proc.stdout

    def inspect(self, run_id: str) -> RunStatus:
        return self._runs.get(run_id, RunStatus.PENDING)
