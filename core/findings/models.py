"""Finding model + lifecycle.

A finding moves through: candidate -> analyzed -> validated -> confirmed.
``Detected != Validated``: a tool signal is only a *candidate* until it is
correlated, reasoned over, and (ideally) proven with a PoC.
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
    evidence: list[str] = field(default_factory=list)
    reproduction: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["status"] = self.status.value
        return d

    def signature(self) -> str:
        """A stable root-cause signature used for dedup.

        Two findings about the same component + root cause should share a
        signature regardless of which agent/tool produced them.
        """
        key = f"{self.affected_component.lower()}::{self.root_cause.lower()}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def make_finding(
    title: str,
    severity: Severity,
    affected_component: str = "",
    root_cause: str = "",
    confidence: Confidence = Confidence.LOW,
    evidence: list[str] | None = None,
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
    )
    return f
