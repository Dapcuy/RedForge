"""Tool layer: the Tool Registry + Tool Executor.

The registry maps *capabilities* (abstract verbs skills declare) to *tools*
(concrete, runnable things). This is the only layer that knows about tools.
"""
from .registry import ToolRegistry
from .executor import ToolExecutor

__all__ = ["ToolRegistry", "ToolExecutor"]
