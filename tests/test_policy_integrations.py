"""Tests for policy engine (hardened: network ordering, scope defaults, fail-closed)."""
import pytest

from core.execution.models import ResourceLimits
from core.models import Target, TargetKind
from core.policy.engine import NETWORK_ORDER, Policy, PolicyEngine, PolicyViolation
from integrations.base import IntegrationConfig
from integrations.caido import CaidoAdapter
from integrations.strix import StrixAdapter


def test_policy_default_blocks_external_url():
    """Fail-closed: an external URL is denied unless explicitly allowed."""
    eng = PolicyEngine(Policy())
    with pytest.raises(PolicyViolation):
        eng.check_target(Target(TargetKind.URL, "https://anything.com"))


def test_policy_default_allows_local_url():
    eng = PolicyEngine(Policy())
    eng.check_target(Target(TargetKind.URL, "https://app.local"))  # no raise
    eng.check_target(Target(TargetKind.URL, "http://127.0.0.1:8080"))  # no raise
    eng.check_target(Target(TargetKind.URL, "http://10.0.0.5"))  # no raise


def test_policy_external_allowed_when_enabled():
    eng = PolicyEngine(Policy(external_targets=True))
    eng.check_target(Target(TargetKind.URL, "https://example.com"))  # no raise


def test_policy_scope_blocks_outside_allowlist():
    policy = Policy(allowed_targets=["*.example.local"], external_targets=False)
    eng = PolicyEngine(policy)
    with pytest.raises(PolicyViolation):
        eng.check_target(Target(TargetKind.URL, "https://evil.com"))


def test_policy_scope_allows_matching():
    policy = Policy(allowed_targets=["*.example.local"], external_targets=False)
    eng = PolicyEngine(policy)
    eng.check_target(Target(TargetKind.URL, "https://app.example.local"))  # no raise


def test_policy_capability_gate():
    eng = PolicyEngine(Policy(allowed_capabilities=["http-analysis"]))
    eng.check_capability("http-analysis")  # ok
    with pytest.raises(PolicyViolation):
        eng.check_capability("port-scanning")


def test_policy_destructive_blocked():
    eng = PolicyEngine(Policy(destructive_actions=False))
    with pytest.raises(PolicyViolation):
        eng.check_destructive("exploit")


def test_policy_destructive_allowed():
    eng = PolicyEngine(Policy(destructive_actions=True))
    eng.check_destructive("exploit")  # no raise


def test_policy_privileged_blocked():
    eng = PolicyEngine(Policy(privileged_runtime=False))
    with pytest.raises(PolicyViolation):
        eng.check_privileged("redforge/privileged:latest")


def test_network_order_is_ordered():
    assert NETWORK_ORDER["none"] < NETWORK_ORDER["bridge"] < NETWORK_ORDER["host"]


def test_network_denied_above_policy_max():
    """A request for host network with policy max none is DENIED, not merged up."""
    eng = PolicyEngine(Policy())
    limits = ResourceLimits(network="host")
    with pytest.raises(PolicyViolation):
        eng.check_network(limits)


def test_network_bridge_denied_when_policy_none():
    eng = PolicyEngine(Policy())
    with pytest.raises(PolicyViolation):
        eng.check_network(ResourceLimits(network="bridge"))


def test_network_at_policy_max_ok():
    eng = PolicyEngine(Policy())
    eng.check_network(ResourceLimits(network="none"))  # no raise


def test_effective_limits_clamp_request_network():
    """Even if a request sets host, effective limits stay at policy max (none)."""
    eng = PolicyEngine(Policy())
    eff = eng.effective_limits("nuclei", ResourceLimits(network="host"))
    assert eff.network == "none"


def test_per_tool_limits_apply():
    policy = Policy(per_tool_limits={"nuclei": {"memory_mb": 1024}})
    eng = PolicyEngine(policy)
    eff = eng.effective_limits("nuclei")
    assert eff.memory_mb == 1024


def test_caido_adapter_unconfigured():
    adapter = CaidoAdapter(IntegrationConfig())
    ev = adapter.run(Target(TargetKind.URL, "https://x"), "r1")
    assert ev.tool == "caido"
    assert "unconfigured" in ev.raw


def test_strix_adapter_unconfigured():
    adapter = StrixAdapter(IntegrationConfig())
    ev = adapter.run(Target(TargetKind.URL, "https://x"), "r1")
    assert ev.tool == "strix"
    assert "stub" in ev.raw
