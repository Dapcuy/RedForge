"""Tool layer: the Tool Registry.

The registry maps *capabilities* (abstract verbs skills declare) to *tools*
(concrete, runnable things). This is the only layer that knows about tools.

Execution goes through ``core.execution.service.ToolExecutionService`` — the
single policy-enforced gate. There is intentionally no standalone executor
exported here (a previous `ToolExecutor` bypassed the policy/workspace gate and
was removed).
"""
from .registry import ToolRegistry

__all__ = ["ToolRegistry"]
