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

Enforcement points: target scope, destructive actions, external targets,
privileged runtime, concurrency cap. Denials are fail-closed.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

import yaml

from ..models import Target, TargetKind


class PolicyViolation(Exception):
    """Raised when a run violates scope or restrictions."""


@dataclass
class Policy:
    allowed_targets: list[str] = field(default_factory=list)
    destructive_actions: bool = False
    external_targets: bool = False
    privileged_runtime: bool = False
    max_parallel_runs: int = 4

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "Policy":
        data = data or {}
        scope = data.get("scope", {}) or {}
        restrictions = data.get("restrictions", {}) or {}
        return cls(
            allowed_targets=list(scope.get("allowed_targets", []) or []),
            destructive_actions=bool(restrictions.get("destructive_actions", False)),
            external_targets=bool(restrictions.get("external_targets", False)),
            privileged_runtime=bool(restrictions.get("privileged_runtime", False)),
            max_parallel_runs=int(restrictions.get("max_parallel_runs", 4)),
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
        if target.kind == TargetKind.URL and not self.policy.external_targets:
            # A URL target is "external" unless it matches the allow-list.
            if not self._in_scope(target):
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


def load_policy(path: str | None) -> Policy:
    """Load policy from a YAML file, or return the default (deny-all-restrictions) policy."""
    if not path:
        return Policy()
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return Policy.from_dict(data.get("policy", data))
