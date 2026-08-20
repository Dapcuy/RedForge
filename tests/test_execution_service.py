"""Tests for the Tool Execution Service (Policy -> Resolver -> Executor -> Runtime)."""
import os

import pytest

from core.execution.models import ExecutionContext, ResourceLimits, ToolRequest
from core.execution.service import ToolExecutionService
from core.ids import scan_id, target_id, tool_request_id
from core.models import Target, TargetKind
from core.policy.engine import Policy, PolicyEngine, PolicyViolation
from core.runtime.base import RunError
from core.tools.registry import ToolRegistry

TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "tools")


class _RecordingRuntime:
    """A fake runtime that records what it was asked to run."""

    name = "fake"

    def __init__(self, result=None, raise_error=None):
        self.calls = []
        self._result = result
        self._raise_error = raise_error

    def command_for(self, tool, target, ctx, limits=None):
        return ["fake", "run", tool.name, target.value]

    def run(self, tool, target, ctx, limits=None):
        self.calls.append((tool.name, target.value, limits))
        if self._raise_error:
            raise self._raise_error
        from core.models import RunResult, RunStatus

        return RunResult(
            run_id=ctx.run_id, tool=tool.name, status=RunStatus.SUCCESS,
            exit_code=0, stdout='{"ok": true}', stderr="",
        )

    def stop(self, run_id):
        pass

    def logs(self, run_id):
        return iter(())

    def inspect(self, run_id):
        return None


def _registry():
    reg = ToolRegistry()
    reg.load_dir(TOOLS_DIR)
    return reg


def _request(capability="vulnerability-scanning", tool_name="", target_value="https://app.example.local"):
    return ToolRequest(
        id=tool_request_id("q"),
        capability=capability,
        target=Target(TargetKind.URL, target_value),
        context=ExecutionContext(
            project_id="prj_1", target_id=target_id(target_value), scan_id=scan_id("s"),
        ),
        tool_name=tool_name,
    )


def test_execution_service_resolves_capability():
    rt = _RecordingRuntime()
    svc = ToolExecutionService(_registry(), rt, PolicyEngine(Policy()))
    outcome = svc.execute(_request(capability="vulnerability-scanning"))
    assert outcome.tool_run.tool_name == "nuclei"
    # artifacts produced for stdout
    assert any(a.kind == "stdout" for a in outcome.artifacts)


def test_execution_service_prefers_named_tool():
    rt = _RecordingRuntime()
    svc = ToolExecutionService(_registry(), rt, PolicyEngine(Policy()))
    outcome = svc.execute(_request(capability="static-analysis", tool_name="slither"))
    assert outcome.tool_run.tool_name == "slither"


def test_execution_service_applies_policy_limits():
    rt = _RecordingRuntime()
    policy = Policy()
    policy.limits.memory_mb = 256
    svc = ToolExecutionService(_registry(), rt, PolicyEngine(policy))
    svc.execute(_request())
    # runtime received the policy-derived limits
    _, _, limits = rt.calls[0]
    assert limits.memory_mb == 256


def test_execution_service_blocks_out_of_scope():
    rt = _RecordingRuntime()
    policy = Policy(allowed_targets=["*.example.local"], external_targets=False)
    svc = ToolExecutionService(_registry(), rt, PolicyEngine(policy))
    with pytest.raises(PolicyViolation):
        svc.execute(_request(target_value="https://evil.com"))


def test_execution_service_blocks_privileged():
    rt = _RecordingRuntime()
    svc = ToolExecutionService(_registry(), rt, PolicyEngine(Policy(privileged_runtime=False)))
    # nmap runs on the privileged image
    with pytest.raises(PolicyViolation):
        svc.execute(_request(capability="port-scanning"))


def test_execution_service_unknown_tool_raises():
    rt = _RecordingRuntime()
    svc = ToolExecutionService(_registry(), rt, PolicyEngine(Policy()))
    with pytest.raises(KeyError):
        svc.execute(_request(tool_name="does-not-exist"))


def test_execution_service_propagates_runtime_error():
    rt = _RecordingRuntime(raise_error=RunError("boom"))
    svc = ToolExecutionService(_registry(), rt, PolicyEngine(Policy()))
    with pytest.raises(RunError):
        svc.execute(_request())


def test_request_limit_cannot_escalate_beyond_policy():
    """A request asking for more memory than policy allows is clamped down."""
    rt = _RecordingRuntime()
    policy = Policy()
    policy.limits.memory_mb = 128
    policy.limits.timeout_s = 60
    svc = ToolExecutionService(_registry(), rt, PolicyEngine(policy))

    req = _request()
    req.limits = ResourceLimits(memory_mb=2048, timeout_s=999)  # escalate attempt
    svc.execute(req)
    _, _, limits = rt.calls[0]
    assert limits.memory_mb == 128
    assert limits.timeout_s == 60
