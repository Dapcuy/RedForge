"""Regression tests for the security hardening fixes (audit review #2)."""
import pytest

from core.execution.models import ExecutionContext, ToolRequest
from core.execution.service import ToolExecutionService
from core.execution.workspace import AuthorizedWorkspaceRegistry
from core.ids import scan_id, target_id, tool_request_id
from core.models import Target, TargetKind
from core.policy.engine import Policy, PolicyEngine
from core.runtime.base import Runtime
from core.tools.registry import ToolRegistry


class _RecordingRuntime(Runtime):
    """Records the RunContext (env) and command without running Docker."""

    def __init__(self):
        self.last_env = {}
        self.last_command = None

    def run(self, tool, target, ctx, limits=None, workspace=None, args=None):
        self.last_env = dict(ctx.env)
        self.last_command = args
        from core.models import RunResult, RunStatus
        return RunResult(
            run_id=ctx.run_id, tool=tool.name, status=RunStatus.SUCCESS, exit_code=0,
            stdout="{}", stderr="", command=str(args), tool_version=tool.runtime.get("version", ""),
        )

    def command_for(self, tool, target, ctx, limits, workspace=None, tool_args=None):
        self.last_command = tool_args
        return ["recording", tool.name, *(tool_args or [])]

    def stop(self, run_id: str) -> None:
        pass

    def logs(self, run_id: str):
        return iter(())

    def inspect(self, run_id: str):
        from core.models import RunStatus
        return RunStatus.SUCCESS


@pytest.fixture
def service():
    reg = ToolRegistry()
    reg.load_dir("tools")
    runtime = _RecordingRuntime()
    policy = Policy()
    svc = ToolExecutionService(reg, runtime, PolicyEngine(policy), workspaces=AuthorizedWorkspaceRegistry())
    return svc, runtime, policy


def _req(tool, capability, env=None, extra=None):
    target = Target(TargetKind.URL, "http://127.0.0.1:9")
    args = dict(extra or {})
    if env is not None:
        args["env"] = env
    return ToolRequest(
        id=tool_request_id("sec", tool),
        capability=capability,
        target=target,
        context=ExecutionContext("p", target_id("t"), scan_id("s")),
        tool_name=tool,
        arguments=args,
    )


def test_executor_bypass_removed():
    """The old ToolExecutor (which called the runtime directly, bypassing
    policy/workspace) must no longer be importable from core.tools."""
    import core.tools as tools_pkg
    assert not hasattr(tools_pkg, "ToolExecutor")
    with pytest.raises(ImportError):
        from core.tools.executor import ToolExecutor  # noqa: F401


def test_env_allowlist_blocks_unlisted(service):
    svc, runtime, _policy = service
    req = _req("httpx", "http-analysis", env={"DOCKER_HOST": "tcp://evil:2375", "HTTP_PROXY": "http://evil"})
    svc.execute(req)
    assert runtime.last_env == {}, f"unlisted env leaked: {runtime.last_env}"


def test_env_allowlist_passes_policy_listed(service):
    svc, runtime, policy = service
    policy.env_allowlist = ["REDFORGE_LOG_LEVEL"]
    req = _req("httpx", "http-analysis", env={"REDFORGE_LOG_LEVEL": "debug", "DOCKER_HOST": "tcp://evil"})
    svc.execute(req)
    assert runtime.last_env == {"REDFORGE_LOG_LEVEL": "debug"}


def test_env_allowlist_passes_manifest_listed(service, tmp_path):
    svc, runtime, _policy = service
    # A tool manifest with env_allowlist allows its own vars.
    manifest = tmp_path / "probe.tool.yaml"
    manifest.write_text(
        "name: probe\n"
        "domain: generic\n"
        "capabilities: [probe]\n"
        "runtime:\n"
        "  image: redforge/test-runtime\n"
        "  entrypoint: probe\n"
        "  version: 1.0.0\n"
        "  env_allowlist: [PROBE_MODE]\n"
        "inputs:\n"
        "  target: url\n"
        "output:\n"
        "  format: json\n",
        encoding="utf-8",
    )
    svc.registry.load_dir(str(tmp_path))
    req = _req("probe", "probe", env={"PROBE_MODE": "x", "SECRET": "y"})
    svc.execute(req)
    assert runtime.last_env == {"PROBE_MODE": "x"}


def test_xss_escaped_in_dashboard():
    """Dashboard JS must escape all user-derived fields."""
    from web.dashboard.app import INDEX_HTML
    # esc() exists and is applied to title/component/severity/status.
    assert "function esc(v)" in INDEX_HTML
    for needle in ("esc(f.title)", "esc(f.affected_component)", "esc(f.severity)", "esc(f.status)"):
        assert needle in INDEX_HTML, f"missing {needle} escape"
    # Raw interpolation must not remain.
    assert "${f.title}" not in INDEX_HTML
    assert "${f.affected_component}" not in INDEX_HTML
