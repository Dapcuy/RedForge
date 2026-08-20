"""Planner: break a repository into focused, parallelizable analysis tasks.

The MVP planner is deterministic: it groups files by language/area and emits
one task per group, each tagged with the capabilities it needs. This is the
'break into focused tasks' step of the open·kritt model.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from ..models import TargetProfile


@dataclass
class Task:
    id: str
    area: str          # e.g. 'backend', 'frontend', 'web3', 'config'
    description: str
    files: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    target: str = ""   # the target this task is about (URL or path)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "area": self.area,
            "description": self.description,
            "files": self.files,
            "capabilities": self.capabilities,
            "target": self.target,
        }


@dataclass
class Plan:
    target: TargetProfile
    tasks: list[Task]

    @property
    def capability_union(self) -> list[str]:
        caps: list[str] = []
        seen: set[str] = set()
        for t in self.tasks:
            for c in t.capabilities:
                if c not in seen:
                    seen.add(c)
                    caps.append(c)
        return caps

    def to_dict(self) -> dict:
        return {
            "target": self.target.to_dict(),
            "tasks": [t.to_dict() for t in self.tasks],
        }


# file extension -> analysis area
_EXT_AREA: dict[str, str] = {
    ".js": "frontend", ".jsx": "frontend", ".ts": "frontend", ".tsx": "frontend",
    ".vue": "frontend", ".css": "frontend", ".scss": "frontend",
    ".py": "backend", ".go": "backend", ".java": "backend", ".rb": "backend",
    ".php": "backend", ".rs": "backend",
    ".sol": "web3", ".vy": "web3",
}

_AREA_CAPS: dict[str, list[str]] = {
    "frontend": ["source-scanning", "http-analysis"],
    "backend": ["source-scanning", "static-analysis"],
    "web3": ["static-analysis", "solidity-analysis"],
    "config": ["source-scanning"],
}


def _collect_files(root: str) -> list[str]:
    files: list[str] = []
    skip = {".git", "node_modules", ".venv", "venv", "target", "dist", "build", ".next"}
    for dirpath, _dirs, fnames in os.walk(root):
        parts = set(dirpath.split(os.sep))
        if parts & skip:
            continue
        for fn in fnames:
            files.append(os.path.join(dirpath, fn))
    return files


def break_repository_into_tasks(root: str, profile: TargetProfile, max_files_per_task: int = 200) -> Plan:
    """Group repository files by analysis area into focused tasks."""
    files = _collect_files(root)
    by_area: dict[str, list[str]] = {}

    for f in files:
        ext = os.path.splitext(f)[1].lower()
        area = _EXT_AREA.get(ext, "config")
        by_area.setdefault(area, []).append(f)

    tasks: list[Task] = []
    tid = 0
    for area in sorted(by_area):
        area_files = by_area[area]
        # split large areas into chunks so tasks stay focused
        for i in range(0, len(area_files), max_files_per_task):
            chunk = area_files[i:i + max_files_per_task]
            tid += 1
            tasks.append(Task(
                id=f"task-{tid:03d}",
                area=area,
                description=f"Analyze {area} code for security issues ({len(chunk)} files)",
                files=chunk,
                capabilities=list(_AREA_CAPS.get(area, ["source-scanning"])),
            ))

    return Plan(target=profile, tasks=tasks)
