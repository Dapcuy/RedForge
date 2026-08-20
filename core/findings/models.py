"""Finding model + lifecycle (hardened).

The real lifecycle is:

    ToolRun -> Artifact -> Evidence -> Correlation -> Validation/Judge -> Finding

A Finding moves through:
    candidate -> analyzed -> validated -> confirmed
or to:
    rejected (false positive)

``Detected != Validated``: a tool signal is only a *candidate* until it is
correlated, reasoned over, and (ideally) proven with a PoC.

Distinction:
- ``FindingCandidate`` (in core/agents + evidence correlation) is an unproven
  hypothesis. It must NOT automatically become a final Finding.
- ``Finding`` (this module) is the persisted, lifecycle-tracked record. Its
  ``status`` starts at CANDIDATE and only advances via explicit validation.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    ANALYZED = "analyzed"
    VALIDATED = "validated"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"  # false positive


class EvidenceLocationKind(str, Enum):
    """Structured evidence locations — better than substring matching."""
    URL = "url"
    ENDPOINT = "endpoint"
    FILE = "file"
    LINE = "line"
    FUNCTION = "function"
    CONTRACT = "contract"
    TRANSACTION = "transaction"
    HOST = "host"


@dataclass
class EvidenceLocation:
    """A structured pointer to where in the target a finding manifests."""
    kind: EvidenceLocationKind
    value: str

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "value": self.value}


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    confidence: Confidence = Confidence.LOW
    status: FindingStatus = FindingStatus.CANDIDATE
    affected_component: str = ""
    root_cause: str = ""
    attack_path: str = ""
    evidence: list[str] = field(default_factory=list)          # evidence ids
    locations: list[EvidenceLocation] = field(default_factory=list)  # structured
    reproduction: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["status"] = self.status.value
        d["locations"] = [loc.to_dict() for loc in self.locations]
        return d

    def signature(self) -> str:
        """A stable root-cause signature used for dedup.

        Uses the structured locations when present (file/line/function), which
        is more precise than substring matching on target/component.
        """
        parts = [self.affected_component.lower(), self.root_cause.lower()]
        for loc in sorted(self.locations, key=lambda l: (l.kind.value, l.value)):
            parts.append(f"{loc.kind.value}:{loc.value.lower()}")
        key = "::".join(parts)
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def make_finding(
    title: str,
    severity: Severity,
    affected_component: str = "",
    root_cause: str = "",
    confidence: Confidence = Confidence.LOW,
    evidence: list[str] | None = None,
    locations: list[EvidenceLocation] | None = None,
    finding_id: str | None = None,
) -> Finding:
    f = Finding(
        id=finding_id or f"fnd_{hashlib.sha256((title + affected_component + root_cause).encode()).hexdigest()[:12]}",
        title=title,
        severity=severity,
        confidence=confidence,
        affected_component=affected_component,
        root_cause=root_cause,
        evidence=list(evidence or []),
        locations=list(locations or []),
    )
    return f
