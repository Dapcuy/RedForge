"""Policy layer: scope + restriction enforcement before tool execution.

Fail-closed by design: any scope/restriction violation refuses the run with a
clear reason. No agent can override policy.
"""
from .engine import Policy, PolicyEngine, PolicyViolation, load_policy

__all__ = ["Policy", "PolicyEngine", "PolicyViolation", "load_policy"]
