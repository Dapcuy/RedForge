"""Tests for the CLI security boundary: redforge run must not bypass authz/policy.

Regression for the audit finding that the CLI used the old ToolExecutor which
called the runtime directly (bypassing AuthorizedWorkspace + Policy).
"""
import os

from core.cli import _build_service, _load_policy, _parse_args_kv
from core.policy.engine import Policy


def test_parse_args_kv():
    assert _parse_args_kv(["json=true", "silent"]) == {"json": "true", "silent": True}


def test_load_policy_default_fail_closed(tmp_path):
    policy = _load_policy(str(tmp_path / "nonexistent.yaml"))
    assert isinstance(policy, Policy)
    assert policy.external_targets is False
    assert policy.destructive_actions is False


def test_build_service_injects_workspace_registry():
    """The CLI service is wired with a workspace registry (no bypass)."""
    reg = _load_registry()
    policy = Policy()
    svc, ws_reg = _build_service(reg, policy)
    assert ws_reg is not None
    assert svc.workspaces is ws_reg


def _load_registry():
    from core.tools.registry import ToolRegistry

    reg = ToolRegistry()
    reg.load_dir(os.path.join(os.path.dirname(__file__), "..", "tools"))
    return reg