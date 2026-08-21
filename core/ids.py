"""Stable, correlation-friendly identifiers for RedForge.

Every durable object has a prefixed, typed ID. IDs are deterministic when a
seed is supplied (so the same logical entity gets the same ID), otherwise
random. Prefixes make an ID's type obvious in logs and in the database.
"""
from __future__ import annotations

import hashlib
import uuid

_PREFIXES: dict[str, str] = {
    "project": "prj",
    "target": "tgt",
    "scan": "scn",
    "task": "tsk",
    "agent_run": "arun",
    "tool_run": "trun",
    "tool_request": "req",
    "artifact": "art",
    "evidence": "ev",
    "finding": "fnd",
    "workspace": "ws",
}


def new_id(kind: str, *seed: str) -> str:
    """Return a typed ID.

    If one or more ``seed`` strings are given, the ID is a stable sha256
    digest of the seed (joined with ``|``). Otherwise it is random.
    """
    prefix = _PREFIXES.get(kind, "id")
    if seed:
        digest = hashlib.sha256("|".join(seed).encode("utf-8")).hexdigest()[:12]
        return f"{prefix}_{digest}"
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def project_id(*seed: str) -> str:
    return new_id("project", *seed)


def target_id(*seed: str) -> str:
    return new_id("target", *seed)


def scan_id(*seed: str) -> str:
    return new_id("scan", *seed)


def task_id(*seed: str) -> str:
    return new_id("task", *seed)


def agent_run_id(*seed: str) -> str:
    return new_id("agent_run", *seed)


def tool_run_id(*seed: str) -> str:
    return new_id("tool_run", *seed)


def tool_request_id(*seed: str) -> str:
    return new_id("tool_request", *seed)


def artifact_id(*seed: str) -> str:
    return new_id("artifact", *seed)


def evidence_id(*seed: str) -> str:
    return new_id("evidence", *seed)


def finding_id(*seed: str) -> str:
    return new_id("finding", *seed)


def workspace_id(*seed: str) -> str:
    return new_id("workspace", *seed)
