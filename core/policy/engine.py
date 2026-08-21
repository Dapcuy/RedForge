"""Policy & Scope engine (hardened).

Model (declarative ``policy.yaml``):

    policy:
      scope:
        allowed_targets: ["*.example.local"]   # empty = local-only (fail-closed)
        allow_local_targets: true              # default true
        allow_external_targets: false          # default false (safe)
      restrictions:
        destructive_actions: false
        privileged_runtime: false
        max_parallel_runs: 4
      limits:
        timeout_s: 300
        cpu: 1.0
        memory_mb: 512
        network: none                          # none | bridge | host
        ...
      per_tool:
        nmap:
          memory_mb: 1024
          network: host

Network access is modeled as an ordered capability:

    none < bridge/egress < host

A request may never escalate network access above the effective policy
maximum. Requested network > policy max is DENIED (not merged upward).

Permissions are separated: target scope, network permission, capability
permission, destructive permission, privileged permission.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

import yaml

from ..execution.models import ResourceLimits, ToolRequest
from ..models import Target, TargetKind

# Ordered network capabilities: none < bridge < host
NETWORK_ORDER: dict[str, int] = {
    "none": 0,
    "bridge": 1,
    "egress": 1,  # bridge/egress are equivalent levels
    "host": 2,
}


class PolicyViolation(Exception):
    """Raised when a run violates scope, permissions, or limits."""


def _network_level(network: str) -> int:
    return NETWORK_ORDER.get(network, 0)


@dataclass
class Policy:
    allowed_targets: list[str] = field(default_factory=list)
    allow_local_targets: bool = True       # default safe: local allowed
    external_targets: bool = False         # default safe: external denied
    destructive_actions: bool = False
    privileged_runtime: bool = False
    max_parallel_runs: int = 4
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    per_tool_limits: dict[str, dict[str, Any]] = field(default_factory=dict)
    allowed_capabilities: list[str] = field(default_factory=list)  # empty = allow all

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Policy:
        data = data or {}
        scope = data.get("scope", {}) or {}
        restrictions = data.get("restrictions", {}) or {}
        limits = data.get("limits", {}) or {}
        return cls(
            allowed_targets=list(scope.get("allowed_targets", []) or []),
            allow_local_targets=bool(scope.get("allow_local_targets", True)),
            external_targets=bool(scope.get("allow_external_targets", False)),
            destructive_actions=bool(restrictions.get("destructive_actions", False)),
            privileged_runtime=bool(restrictions.get("privileged_runtime", False)),
            max_parallel_runs=int(restrictions.get("max_parallel_runs", 4)),
            limits=ResourceLimits.from_dict(limits),
            per_tool_limits=dict(data.get("per_tool", {}) or {}),
            allowed_capabilities=list(restrictions.get("allowed_capabilities", []) or []),
        )


class PolicyEngine:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    # ---- Target scope ----
    def _is_local(self, target: Target) -> bool:
        """Local = loopback / RFC1918 / localhost / *.local. External otherwise."""
        value = target.value
        if target.kind != TargetKind.URL:
            return True
        host = value.split("://", 1)[-1].split("/", 1)[0].lower()
        host = host.split(":")[0]
        if host in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}:
            return True
        if host.endswith((".local", ".localhost")):
            return True
        if host.startswith(("127.", "10.", "192.168.")):
            return True
        if host.startswith("172."):
            parts = host.split(".")
            if len(parts) == 4:
                try:
                    return 16 <= int(parts[1]) <= 31
                except ValueError:
                    return False
        return False

    def _in_scope(self, target: Target) -> bool:
        if self.policy.allowed_targets:
            value = target.value
            for pattern in self.policy.allowed_targets:
                if fnmatch.fnmatch(value, pattern) or fnmatch.fnmatch(value, f"*{pattern}"):
                    return True
            return False
        # No allow-list: fail-closed default depends on local vs external.
        if self._is_local(target):
            return self.policy.allow_local_targets
        return self.policy.external_targets

    def check_target(self, target: Target) -> None:
        if not self._in_scope(target):
            reason = "local target not allowed" if self._is_local(target) else "external target not allowed"
            raise PolicyViolation(
                f"target {target.display} is out of scope ({reason}; allowed: {self.policy.allowed_targets or 'none'})"
            )

    # ---- Capability permission ----
    def check_capability(self, capability: str) -> None:
        if not self.policy.allowed_capabilities:
            return
        if capability not in self.policy.allowed_capabilities:
            raise PolicyViolation(
                f"capability '{capability}' is not allowed by policy "
                f"(allowed: {self.policy.allowed_capabilities})"
            )

    # ---- Destructive permission ----
    def check_destructive(self, action: str) -> None:
        destructive = {"exploit", "intrusive", "dos", "sqlmap", "destructive"}
        if action.lower() in destructive and not self.policy.destructive_actions:
            raise PolicyViolation(f"destructive action '{action}' is disabled by policy")

    # ---- Privileged permission ----
    def check_privileged(self, image: str) -> None:
        if "privileged" in image and not self.policy.privileged_runtime:
            raise PolicyViolation("privileged runtime is disabled by policy")

    # ---- Network permission (ordered capability, deny escalation) ----
    def check_network(self, limits: ResourceLimits) -> None:
        """Deny if the effective limits request more network than the policy max.

        This is the ONLY network check: the policy's own limits are the maximum,
        and request-level limits can never raise the level (they are merged
        restrictively, and this check is a final fail-closed guard).
        """
        policy_level = _network_level(self.policy.limits.network)
        requested_level = _network_level(limits.network)
        if requested_level > policy_level:
            raise PolicyViolation(
                f"network '{limits.network}' exceeds policy maximum "
                f"'{self.policy.limits.network}'"
            )

    # ---- Effective limits (most-restrictive-wins) ----
    def effective_limits(self, tool_name: str, requested: ResourceLimits | None = None) -> ResourceLimits:
        base = ResourceLimits(
            timeout_s=self.policy.limits.timeout_s,
            cpu=self.policy.limits.cpu,
            memory_mb=self.policy.limits.memory_mb,
            pids_limit=self.policy.limits.pids_limit,
            read_only_fs=self.policy.limits.read_only_fs,
            network=self.policy.limits.network,
            max_output_bytes=self.policy.limits.max_output_bytes,
        )

        # Per-tool overrides are policy-authoritative: the operator explicitly
        # configures them, so they may raise scalar limits (e.g. nmap needs more
        # memory) — but they may NEVER raise the network level beyond the policy
        # maximum (network is checked separately via check_network).
        tool_override = self.policy.per_tool_limits.get(tool_name, {})
        if tool_override:
            override = ResourceLimits.from_dict(tool_override)
            base.timeout_s = override.timeout_s
            base.cpu = override.cpu
            base.memory_mb = override.memory_mb
            base.pids_limit = override.pids_limit
            base.read_only_fs = base.read_only_fs or override.read_only_fs
            base.max_output_bytes = override.max_output_bytes
            # Network is ONLY overridden when the per-tool config explicitly
            # sets it; an unset network must never downgrade the policy level
            # (a per-tool {memory} config must not silently disable networking).
            if "network" in tool_override and _network_level(override.network) <= _network_level(self.policy.limits.network):
                base.network = override.network
            # else: network stays at policy level; check_network enforces it.

        # Request-level limits are always merged restrictively (min) so a
        # request can never escalate beyond what policy allows.
        if requested is not None:
            base = self._merge_restrictive(base, requested)

        return base

    @staticmethod
    def _merge_restrictive(policy_limits: ResourceLimits, other: ResourceLimits) -> ResourceLimits:
        """Merge two limits, taking the *more restrictive* value for each scalar.

        Network: the effective level is the MINIMUM of the two — a request can
        never widen network access. read_only_fs ORs (either can force read-only).
        """
        eff_network = policy_limits.network
        if _network_level(other.network) < _network_level(policy_limits.network):
            eff_network = other.network
        return ResourceLimits(
            timeout_s=min(policy_limits.timeout_s, other.timeout_s),
            cpu=min(policy_limits.cpu, other.cpu),
            memory_mb=min(policy_limits.memory_mb, other.memory_mb),
            pids_limit=min(policy_limits.pids_limit, other.pids_limit),
            read_only_fs=policy_limits.read_only_fs or other.read_only_fs,
            network=eff_network,
            max_output_bytes=min(policy_limits.max_output_bytes, other.max_output_bytes),
        )

    def check_request(self, request: ToolRequest, tool_name: str) -> ResourceLimits:
        """Full pre-execution check for a ToolRequest; returns effective limits.

        Order: capability -> target scope -> destructive -> limits (network).
        Raises PolicyViolation on any denial. This is the single gate every
        tool execution passes.
        """
        self.check_capability(request.capability)
        self.check_target(request.target)
        self.check_destructive(request.capability)
        limits = self.effective_limits(tool_name, request.limits)
        self.check_network(limits)
        return limits


def load_policy(path: str | None) -> Policy:
    """Load policy from a YAML file, or return the default (fail-closed) policy."""
    if not path:
        return Policy()
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return Policy.from_dict(data.get("policy", data))
