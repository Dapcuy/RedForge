"""Evidence model and normalization helpers (provenance-aware).

Evidence is a core component. Every tool run produces evidence; the Finding
engine only trusts evidence. ``raw`` is immutable (original output + digest);
``normalized`` is the structured, queryable form.

Provenance: evidence references scan_id, tool_run_id, target, tool, tool
version, timestamps, source, and artifact/hash where applicable, so any
finding can be traced back to the exact tool run that produced it.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from ..ids import evidence_id as new_evidence_id


class EvidenceType(str, Enum):
    HTTP = "http"
    CODE = "code"
    SMART_CONTRACT = "smart-contract"
    FUZZ = "fuzz"
    POC = "poc"
    HTTP_INTERACTION = "http-interaction"
    DYNAMIC = "dynamic"
    GENERIC = "generic"


def utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class Evidence:
    id: str
    scan_id: str
    tool_run_id: str
    tool: str
    type: EvidenceType
    target: str
    raw: str
    tool_version: str = ""
    source: str = ""            # which agent/tool produced this
    raw_format: str = "text"
    artifact_id: str = ""       # artifact reference, if raw is stored as a blob
    artifact_sha256: str = ""   # hash of the raw payload
    normalized: dict[str, Any] | None = None
    created_at: str = field(default_factory=utcnow_iso)

    @property
    def digest(self) -> str:
        return self.artifact_sha256 or hashlib.sha256(self.raw.encode("utf-8")).hexdigest()

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
    scan_id: str,
    tool_run_id: str,
    tool: str,
    target: str,
    raw: str,
    raw_format: str = "text",
    tool_version: str = "",
    source: str = "",
    artifact_id: str = "",
    normalized: dict[str, Any] | None = None,
    evidence_id: str | None = None,
) -> Evidence:
    """Create a provenance-aware Evidence record.

    ``run_id`` (legacy alias) is accepted via the positional scan_id/tool_run_id
    ordering for backward compatibility is intentionally *not* kept: the new
    signature is explicit. Callers should pass scan_id and tool_run_id.
    """
    raw_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return Evidence(
        id=evidence_id or new_evidence_id(scan_id, tool_run_id, tool),
        scan_id=scan_id,
        tool_run_id=tool_run_id,
        tool=tool,
        type=evidence_type_for_tool(tool),
        target=target,
        raw=raw,
        raw_format=raw_format,
        tool_version=tool_version,
        source=source,
        artifact_id=artifact_id,
        artifact_sha256=raw_hash,
        normalized=normalized,
    )
