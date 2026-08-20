"""Tests for the Runtime layer (interface + DockerRuntime).

We monkeypatch ``subprocess.run`` instead of writing a fake docker binary, so
the tests are cross-platform (Windows/Linux/macOS) and don't depend on a shell.
"""
import subprocess
from types import SimpleNamespace

import pytest

from core.models import RunContext, Target, TargetKind, Tool
from core.runtime.base import DockerRuntime, RunError


def _result(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _httpx_tool() -> Tool:
    return Tool(
        name="httpx", domain="web", capabilities=["http-analysis"],
        runtime={"image": "redforge/web-runtime", "entrypoint": "httpx"},
        inputs={"target": "url"}, output={"format": "json"},
    )


def test_docker_runtime_runs_tool(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        return _result(0, stdout="fake stdout\n")

    monkeypatch.setattr(subprocess, "run", fake_run)

    rt = DockerRuntime()
    result = rt.run(
        _httpx_tool(), Target(TargetKind.URL, "https://example.com"),
        RunContext(run_id="r1"),
    )

    assert result.status.value == "success"
    assert result.exit_code == 0
    assert "fake stdout" in result.stdout

    # First subprocess call is the daemon check (docker info).
    assert calls[0][:2] == ["docker", "info"]
    # Second is the actual run; last args are image + entrypoint + target.
    run_call = calls[1]
    assert run_call[0] == "docker"
    assert "redforge/web-runtime" in run_call
    assert run_call[-2:] == ["httpx", "https://example.com"]


def test_docker_runtime_checks_daemon(monkeypatch):
    def fake_run(args, **kwargs):
        if args[1] == "info":
            return _result(1, stderr="daemon down")
        return _result(0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    rt = DockerRuntime()
    with pytest.raises(RunError):
        rt.run(_httpx_tool(), Target(TargetKind.URL, "x"), RunContext(run_id="r2"))


def test_docker_runtime_timeout(monkeypatch):
    state = {"n": 0}

    def fake_run(args, **kwargs):
        state["n"] += 1
        if state["n"] >= 2:  # fail on the actual run, not the daemon check
            raise subprocess.TimeoutExpired(cmd="docker", timeout=1)
        return _result(0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    rt = DockerRuntime()
    with pytest.raises(RunError):
        rt.run(_httpx_tool(), Target(TargetKind.URL, "x"), RunContext(run_id="r3"))
