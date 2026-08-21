"""Tool Registry: capability -> tool mapping, loaded from declarative manifests."""
from __future__ import annotations

import glob
import os
from collections import defaultdict
from collections.abc import Iterable
from typing import ClassVar

import yaml

from ..models import Tool


class ToolRegistry:
    """Holds all known tools and resolves capabilities to tools.

    Manifests are declarative YAML. Adding a tool = adding a manifest file
    (plus its runtime image); no code changes.
    """

    VALID_DOMAINS: ClassVar[set[str]] = {"web", "code", "web3", "network", "cloud", "generic"}

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._by_capability: dict[str, list[Tool]] = defaultdict(list)

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"duplicate tool name: {tool.name}")
        if tool.domain not in self.VALID_DOMAINS:
            raise ValueError(f"tool {tool.name} has unknown domain: {tool.domain}")
        if not tool.capabilities:
            raise ValueError(f"tool {tool.name} declares no capabilities")
        self._tools[tool.name] = tool
        for cap in tool.capabilities:
            self._by_capability[cap].append(tool)

    def load_dir(self, path: str) -> int:
        """Load all ``*.tool.yaml`` manifests under a directory. Returns count."""
        count = 0
        for fname in sorted(glob.glob(os.path.join(path, "**", "*.tool.yaml"), recursive=True)):
            with open(fname, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            self.register(Tool.from_manifest(data))
            count += 1
        return count

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def resolve_capability(self, capability: str, preferred: str | None = None) -> Tool:
        """Resolve a capability to a single tool (deterministic).

        Order:
        1. ``preferred`` tool, if registered and satisfies the capability.
        2. Highest ``priority`` (tie broken by name for determinism).
        """
        tools = self._by_capability.get(capability, [])
        if not tools:
            raise KeyError(f"no tool registered for capability: {capability}")
        if preferred:
            for tool in tools:
                if tool.name == preferred:
                    return tool
        # Deterministic: highest priority, ties broken by name (ascending).
        return min(tools, key=lambda t: (-t.priority, t.name))

    def validate_arguments(self, tool: Tool, arguments: dict) -> None:
        """Validate ToolRequest arguments against the tool's input schema.

        The schema (``input_schema``) lists accepted keys; each may declare
        ``required`` (bool) and ``type``. Unknown keys are rejected — an agent
        cannot smuggle arbitrary arguments (e.g. mount flags) to a tool.
        """
        schema = tool.input_schema
        if not schema:
            return  # no schema -> no extra validation
        known = set(schema)
        # `env` is a SYSTEM argument (filtered by the execution service's
        # allowlist); it is never a tool argument.
        known.add("env")
        provided = set(arguments)
        unknown = provided - known
        if unknown:
            raise ValueError(
                f"tool {tool.name} got unknown arguments: {sorted(unknown)} "
                f"(allowed: {sorted(known)})"
            )
        for key, spec in schema.items():
            spec = spec if isinstance(spec, dict) else {"type": str(spec)}
            if spec.get("required") and key not in provided:
                raise ValueError(f"tool {tool.name} requires argument '{key}'")
            if key in provided and spec.get("type") == "string" and not isinstance(arguments[key], str):
                raise ValueError(f"tool {tool.name} argument '{key}' must be a string")

    def resolve_many(self, capabilities: Iterable[str], preferred: str | None = None) -> list[Tool]:
        """Resolve a set of capabilities, deduping by tool name."""
        seen: dict[str, Tool] = {}
        for cap in capabilities:
            try:
                tool = self.resolve_capability(cap, preferred)
            except KeyError:
                continue  # capability unsupported -> skip, planner reports later
            seen[tool.name] = tool
        return list(seen.values())

    @property
    def tools(self) -> dict[str, Tool]:
        return dict(self._tools)

    def capabilities(self) -> list[str]:
        return sorted(self._by_capability)
