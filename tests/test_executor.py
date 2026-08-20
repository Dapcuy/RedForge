"""Tests for the Tool Executor (capability/tool -> runtime)."""
import os

from core.models import RunContext, Target, TargetKind
from core.tools.executor import ToolExecutor
from core.tools.registry import ToolRegistry


class _NoopRuntime:
    name = "noop"

    def run(self, tool, target, ctx):
        return (tool.name, target.value, ctx.run_id)

    def stop(self, run_id):
        pass

    def logs(self, run_id):
        return iter(())

    def inspect(self, run_id):
        return None


def test_executor_runs_capability():
    reg = ToolRegistry()
    reg.load_dir(os.path.join(os.path.dirname(__file__), "..", "tools"))
    ex = ToolExecutor(reg, _NoopRuntime())

    out = ex.run_capability(
        "vulnerability-scanning",
        Target(TargetKind.URL, "https://example.com"),
        RunContext(run_id="r1"),
    )
    assert out[0] == "nuclei"


def test_executor_unknown_tool_raises():
    reg = ToolRegistry()
    reg.load_dir(os.path.join(os.path.dirname(__file__), "..", "tools"))
    ex = ToolExecutor(reg, _NoopRuntime())

    import pytest

    with pytest.raises(KeyError):
        ex.run_tool("nope", Target(TargetKind.URL, "x"), RunContext(run_id="r1"))
