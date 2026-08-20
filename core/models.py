"""Shared data models for RedForge.

These are the canonical in-memory shapes used across layers. They are plain
dataclasses (no external deps) so every layer can import them without
pulling in a framework.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class TargetKind(str, Enum):
    URL = "url"
    REPO = "repo"
    SOURCE_DIR = "source-dir"


@dataclass
class Target:
    """What we are analyzing: a running URL, a git repo, or a local source dir."""
    kind: TargetKind
    value: str

    @property
    def display(self) -> str:
        return f"{self.kind.value}:{self.value}"


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class RunResult:
    """The normalized result of a single tool execution (runtime-layer)."""
    run_id: str
    tool: str
    status: RunStatus
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    artifacts: list[str] = field(default_factory=list)
    duration_ms: int = 0
    tool_version: str = ""
    command: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class RunContext:
    """Per-run execution parameters passed through the runtime interface."""
    run_id: str
    workdir: str = ""
    timeout_s: int = 300
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class Tool:
    """A concrete security tool, parsed from a declarative manifest."""
    name: str
    domain: str
    capabilities: list[str]
    runtime: dict[str, Any]
    inputs: dict[str, Any]
    output: dict[str, Any]

    @classmethod
    def from_manifest(cls, data: dict[str, Any]) -> Tool:
        required = {"name", "domain", "capabilities", "runtime", "inputs", "output"}
        missing = required - set(data)
        if missing:
            raise ValueError(f"tool manifest missing fields: {sorted(missing)}")
        return cls(
            name=data["name"],
            domain=data["domain"],
            capabilities=list(data["capabilities"]),
            runtime=dict(data["runtime"]),
            inputs=dict(data["inputs"]),
            output=dict(data["output"]),
        )

    @property
    def image(self) -> str:
        return self.runtime.get("image", "")

    @property
    def entrypoint(self) -> str:
        return self.runtime.get("entrypoint", self.name)


@dataclass
class TargetProfile:
    """The tech-stack fingerprint of a target (populated by the profiler)."""
    target: Target
    technologies: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
