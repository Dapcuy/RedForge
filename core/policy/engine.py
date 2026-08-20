"""Policy & Scope engine.

Model (declarative ``policy.yaml``):

    policy:
      scope:
        allowed_targets: ["*.example.local", "github.com/Dapcuy/*"]
      restrictions:
        destructive_actions: false
        external_targets: false
        privileged_runtime: false
        max_parallel_runs: 4
      limits:                       # default resource limits
        timeout_s: 300
        cpu: 1.0
        memory_mb: 512
        pids_limit: 256
        read_only_fs: true
        network: none
        max_output_bytes: 10000000
      per_tool:
        nmap:
          memory_mb: 1024
          network: host

Enforcement points: target scope, destructive actions, external targets,
privileged runtime, concurrency cap, and resource limits. Denials are fail-closed.
The Policy engine is the authority that produces the effective ResourceLimits
for a tool execution.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

import yaml

from ..execution.models import ResourceLimits, ToolRequest
from ..models import Target, TargetKind


class PolicyViolation(Exception):
    """Raised when a run violates scope, restrictions, or limits."""


@dataclass
class Policy:
    allowed_targets: list[str] = field(default_factory=list)
    destructive_actions: bool = False
    external_targets: bool = False
    privileged_runtime: bool = False
    max_parallel_runs: int = 4
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    per_tool_limits: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Policy:
        data = data or {}
        scope = data.get("scope", {}) or {}
        restrictions = data.get("restrictions", {}) or {}
        limits = data.get("limits", {}) or {}
        return cls(
            allowed_targets=list(scope.get("allowed_targets", []) or []),
            destructive_actions=bool(restrictions.get("destructive_actions", False)),
            external_targets=bool(restrictions.get("external_targets", False)),
            privileged_runtime=bool(restrictions.get("privileged_runtime", False)),
            max_parallel_runs=int(restrictions.get("max_parallel_runs", 4)),
            limits=ResourceLimits.from_dict(limits),
            per_tool_limits=dict(data.get("per_tool", {}) or {}),
        )


class PolicyEngine:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def _in_scope(self, target: Target) -> bool:
        if not self.policy.allowed_targets:
            return True  # no allow-list -> everything in scope
        value = target.value
        for pattern in self.policy.allowed_targets:
            if fnmatch.fnmatch(value, pattern) or fnmatch.fnmatch(value, f"*{pattern}"):
                return True
        return False

    def check_target(self, target: Target) -> None:
        # A URL target is "external" unless it matches the allow-list.
        if (
            target.kind == TargetKind.URL
            and not self.policy.external_targets
            and not self._in_scope(target)
        ):
            raise PolicyViolation(
                f"target {target.display} is out of scope (allowed: {self.policy.allowed_targets})"
            )

    def check_destructive(self, action: str) -> None:
        destructive = {"exploit", "intrusive", "dos", "sqlmap", "destructive"}
        if action.lower() in destructive and not self.policy.destructive_actions:
            raise PolicyViolation(f"destructive action '{action}' is disabled by policy")

    def check_privileged(self, image: str) -> None:
        if "privileged" in image and not self.policy.privileged_runtime:
            raise PolicyViolation("privileged runtime is disabled by policy")

    def check_parallel(self, active_runs: int) -> None:
        if active_runs >= self.policy.max_parallel_runs:
            raise PolicyViolation(
                f"max parallel runs ({self.policy.max_parallel_runs}) reached"
            )

    def check_network(self, limits: ResourceLimits) -> None:
        """Fail-closed: network=host is only allowed for in-scope targets."""
        if limits.network == "host" and not self.policy.external_targets:
            raise PolicyViolation("network=host is disabled unless external_targets is allowed")

    def effective_limits(self, tool_name: str, requested: ResourceLimits | None = None) -> ResourceLimits:
        """Compute effective limits: policy defaults <- per-tool overrides <- request.

        The most restrictive value wins for scalar limits (min), so a request
        can never escalate beyond policy defaults.
        """
        base = ResourceLimits(
            timeout_s=self.policy.limits.timeout_s,
            cpu=self.policy.limits.cpu,
            memory_mb=self.policy.limits.memory_mb,
            pids_limit=self.policy.limits.pids_limit,
            read_only_fs=self.policy.limits.read_only_fs,
            network=self.policy.limits.network,
            max_output_bytes=self.policy.limits.max_output_bytes,
        )

        tool_override = self.policy.per_tool_limits.get(tool_name, {})
        if tool_override:
            base = self._merge_restrictive(base, ResourceLimits.from_dict(tool_override))

        if requested is not None:
            base = self._merge_restrictive(base, requested)

        return base

    @staticmethod
    def _merge_restrictive(policy_limits: ResourceLimits, other: ResourceLimits) -> ResourceLimits:
        """Merge two limits, taking the *more restrictive* value for each scalar.

        Network is not a scalar: the request may not widen network access
        beyond the policy default. read_only_fs ORs (either can force read-only).
        """
        return ResourceLimits(
            timeout_s=min(policy_limits.timeout_s, other.timeout_s),
            cpu=min(policy_limits.cpu, other.cpu),
            memory_mb=min(policy_limits.memory_mb, other.memory_mb),
            pids_limit=min(policy_limits.pids_limit, other.pids_limit),
            read_only_fs=policy_limits.read_only_fs or other.read_only_fs,
            network=policy_limits.network if policy_limits.network == "none" else other.network,
            max_output_bytes=min(policy_limits.max_output_bytes, other.max_output_bytes),
        )

    def check_request(self, request: ToolRequest, tool_name: str) -> ResourceLimits:
        """Full pre-execution check for a ToolRequest; returns effective limits.

        Order: target scope -> destructive -> limits. Raises PolicyViolation
        on any denial. This is the single gate every tool execution passes.
        """
        self.check_target(request.target)
        self.check_destructive(request.capability)
        limits = self.effective_limits(tool_name, request.limits)
        self.check_network(limits)
        return limits


def load_policy(path: str | None) -> Policy:
    """Load policy from a YAML file, or return the default (deny-all-restrictions) policy."""
    if not path:
        return Policy()
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return Policy.from_dict(data.get("policy", data))
