"""Tool layer: the Tool Registry + Tool Executor.

The registry maps *capabilities* (abstract verbs skills declare) to *tools*
(concrete, runnable things). This is the only layer that knows about tools.
"""
from .executor import ToolExecutor
from .registry import ToolRegistry

__all__ = ["ToolExecutor", "ToolRegistry"]
