"""Tool Executor: runs a resolved tool through the Runtime Interface.

The layering rule (enforced from Phase 0):

    Skill --requires--> Capability --resolved by--> Tool --runs on--> Runtime
"""
from __future__ import annotations

from ..models import RunContext, RunResult, Target
from ..runtime.base import Runtime
from .registry import ToolRegistry


class ToolExecutor:
    """Resolves capabilities to tools and executes them via a runtime."""

    def __init__(self, registry: ToolRegistry, runtime: Runtime) -> None:
        self.registry = registry
        self.runtime = runtime

    def run_capability(
        self,
        capability: str,
        target: Target,
        ctx: RunContext,
        preferred: str | None = None,
    ) -> RunResult:
        tool = self.registry.resolve_capability(capability, preferred)
        return self.runtime.run(tool, target, ctx)

    def run_tool(self, tool_name: str, target: Target, ctx: RunContext) -> RunResult:
        tool = self.registry.get(tool_name)
        if tool is None:
            raise KeyError(f"unknown tool: {tool_name}")
        return self.runtime.run(tool, target, ctx)
