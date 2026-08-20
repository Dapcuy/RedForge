"""Integration tests: policy -> tool resolver -> runtime (the full execution chain).

These exercise the real ToolExecutionService with the real ToolRegistry and
PolicyEngine, but a fake Runtime (no Docker daemon), so the integration is
deterministic and fast.
"""
import os

import pytest

from core.execution.models import ExecutionContext, ToolRequest
from core.execution.service import ToolExecutionService
from core.ids import scan_id, target_id, tool_request_id
from core.models import RunResult, RunStatus, Target, TargetKind
from core.policy.engine import Policy, PolicyEngine, PolicyViolation
from core.runtime.base import RunError
from core.tools.registry import ToolRegistry

TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "tools")


class _FakeRuntime:
    name = "fake"

    def __init__(self, fail_tool=None):
        self.calls = []
        self._fail_tool = fail_tool

    def command_for(self, tool, target, ctx, limits=None, workspace=None, args=None):
        return ["fake", tool.name, target.value]

    def run(self, tool, target, ctx, limits=None, workspace=None, args=None):
        self.calls.append((tool.name, limits))
        if self._fail_tool and tool.name == self._fail_tool:
            raise RunError(f"{tool.name} failed")
        return RunResult(
            run_id=ctx.run_id, tool=tool.name, status=RunStatus.SUCCESS,
            exit_code=0, stdout="ok", stderr="", tool_version=tool.runtime.get("version", ""),
        )

    def stop(self, run_id):
        pass

    def logs(self, run_id):
        return iter(())

    def inspect(self, run_id):
        return None


def _svc(runtime, **policy_kwargs):
    reg = ToolRegistry()
    reg.load_dir(TOOLS_DIR)
    # default to allowing the external test target; tests that check scope
    # explicitly pass external_targets=False.
    policy_kwargs.setdefault("external_targets", True)
    policy = Policy(**policy_kwargs)
    return ToolExecutionService(reg, runtime, PolicyEngine(policy))


def _request(capability, target_value="https://app.example.local", limits=None):
    return ToolRequest(
        id=tool_request_id("i"),
        capability=capability,
        target=Target(TargetKind.URL, target_value),
        context=ExecutionContext("prj", target_id(target_value), scan_id("s")),
        limits=limits,
    )


def test_integration_policy_resolver_runtime():
    rt = _FakeRuntime()
    svc = _svc(rt, allowed_targets=["*.example.local"], external_targets=True)
    outcome = svc.execute(_request("vulnerability-scanning"))
    assert outcome.tool_run.tool_name == "nuclei"
    assert rt.calls[0][0] == "nuclei"
    # limits flowed through policy -> runtime
    limits = rt.calls[0][1]
    assert limits.network == "none"  # default (external_targets does not force host)


def test_integration_policy_blocks_out_of_scope_before_runtime():
    rt = _FakeRuntime()
    svc = _svc(rt, allowed_targets=["*.example.local"], external_targets=False)
    with pytest.raises(PolicyViolation):
        svc.execute(_request("vulnerability-scanning", target_value="https://evil.com"))
    assert rt.calls == []  # never reached the runtime


def test_integration_runtime_error_propagates():
    rt = _FakeRuntime(fail_tool="nuclei")
    svc = _svc(rt, external_targets=True)
    with pytest.raises(RunError):
        svc.execute(_request("vulnerability-scanning"))


def test_integration_resolves_capability_to_correct_tool():
    rt = _FakeRuntime()
    svc = _svc(rt, external_targets=True)
    req = _request("static-analysis")
    # semgrep has the highest priority for static-analysis and requires a path
    req.arguments = {"path": "src"}
    outcome = svc.execute(req)
    assert outcome.tool_run.tool_name == "semgrep"
