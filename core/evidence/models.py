"""Evidence model and normalization helpers.

Evidence is a core component. Every tool run produces evidence; the Finding
engine only trusts evidence. ``raw`` is immutable (original output + digest);
``normalized`` is the structured, queryable form.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EvidenceType(str, Enum):
    HTTP = "http"
    CODE = "code"
    SMART_CONTRACT = "smart-contract"
    FUZZ = "fuzz"
    POC = "poc"
    HTTP_INTERACTION = "http-interaction"
    DYNAMIC = "dynamic"
    GENERIC = "generic"


@dataclass
class Evidence:
    id: str
    run_id: str
    tool: str
    type: EvidenceType
    target: str
    raw_format: str
    raw: str
    normalized: dict[str, Any] | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        d["digest"] = self.digest
        return d


def evidence_type_for_tool(tool: str) -> EvidenceType:
    """Map a tool name to its evidence type (per the spec's source table)."""
    mapping = {
        "nuclei": EvidenceType.HTTP,
        "httpx": EvidenceType.HTTP,
        "ffuf": EvidenceType.HTTP,
        "semgrep": EvidenceType.CODE,
        "slither": EvidenceType.SMART_CONTRACT,
        "echidna": EvidenceType.FUZZ,
        "foundry": EvidenceType.POC,
        "caido": EvidenceType.HTTP_INTERACTION,
        "strix": EvidenceType.DYNAMIC,
    }
    return mapping.get(tool, EvidenceType.GENERIC)


def make_evidence(
    run_id: str,
    tool: str,
    target: str,
    raw: str,
    raw_format: str = "text",
    normalized: dict[str, Any] | None = None,
    evidence_id: str | None = None,
) -> Evidence:
    return Evidence(
        id=evidence_id or f"ev_{hashlib.sha256((run_id + tool + raw).encode()).hexdigest()[:12]}",
        run_id=run_id,
        tool=tool,
        type=evidence_type_for_tool(tool),
        target=target,
        raw_format=raw_format,
        raw=raw,
        normalized=normalized,
    )
