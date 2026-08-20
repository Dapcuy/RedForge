"""Tests for policy engine and integration adapters."""
import pytest

from core.models import Target, TargetKind
from core.policy.engine import Policy, PolicyEngine, PolicyViolation
from integrations.base import IntegrationConfig
from integrations.caido import CaidoAdapter
from integrations.strix import StrixAdapter


def test_policy_allow_all_by_default():
    eng = PolicyEngine(Policy())
    eng.check_target(Target(TargetKind.URL, "https://anything.com"))  # no raise


def test_policy_scope_blocks_external_url():
    policy = Policy(allowed_targets=["*.example.local"], external_targets=False)
    eng = PolicyEngine(policy)
    with pytest.raises(PolicyViolation):
        eng.check_target(Target(TargetKind.URL, "https://evil.com"))


def test_policy_scope_allows_matching():
    policy = Policy(allowed_targets=["*.example.local"], external_targets=False)
    eng = PolicyEngine(policy)
    eng.check_target(Target(TargetKind.URL, "https://app.example.local"))  # no raise


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


def test_policy_parallel_cap():
    eng = PolicyEngine(Policy(max_parallel_runs=2))
    eng.check_parallel(1)  # ok
    with pytest.raises(PolicyViolation):
        eng.check_parallel(2)


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
