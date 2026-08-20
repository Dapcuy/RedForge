"""Finding Engine: dedup -> correlation -> judge.

Solves the classic failure: 10 agents -> 10 findings -> actually 2 vulns.

- **Dedup** merges findings that share a (component, root-cause) signature.
- **Correlation** attaches evidence to the surviving finding.
- **Judge** ranks findings by severity + confidence and returns the final list.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..evidence.models import Evidence
from .models import Confidence, Finding, Severity, make_finding

_SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 1,
}


@dataclass
class CorrelatedFinding:
    finding: Finding
    evidence_ids: list[str] = field(default_factory=list)


class FindingEngine:
    def __init__(self) -> None:
        self._by_signature: dict[str, Finding] = {}
        self._evidence_of: dict[str, list[str]] = {}

    def add_candidate(
        self,
        title: str,
        severity: Severity,
        affected_component: str = "",
        root_cause: str = "",
        confidence: Confidence = Confidence.LOW,
        evidence_ids: list[str] | None = None,
    ) -> Finding:
        """Add a candidate; dedup by (component, root-cause) signature."""
        probe = make_finding(title, severity, affected_component, root_cause, confidence)
        sig = probe.signature()

        existing = self._by_signature.get(sig)
        if existing is None:
            existing = probe
            self._by_signature[sig] = existing
            self._evidence_of[sig] = []
        else:
            # Merge: keep the higher severity/confidence; union evidence.
            existing.severity = max(existing.severity, severity, key=lambda s: _SEVERITY_ORDER[s])
            existing.confidence = max(existing.confidence, confidence, key=lambda c: [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH].index(c))

        for ev in evidence_ids or []:
            if ev not in existing.evidence:
                existing.evidence.append(ev)
            if ev not in self._evidence_of[sig]:
                self._evidence_of[sig].append(ev)

        return existing

    def correlate(self, evidence: list[Evidence]) -> None:
        """Attach evidence to findings by matching evidence.target to finding."""
        # Correlation key: (tool -> component). In the MVP we link evidence that
        # references the same target as a finding's affected_component.
        by_target: dict[str, list[str]] = {}
        for ev in evidence:
            by_target.setdefault(ev.target, []).append(ev.id)

        for sig, finding in self._by_signature.items():
            comp = finding.affected_component
            for target, ev_ids in by_target.items():
                if target and comp and (target in comp or comp in target):
                    for eid in ev_ids:
                        if eid not in finding.evidence:
                            finding.evidence.append(eid)
                        if eid not in self._evidence_of[sig]:
                            self._evidence_of[sig].append(eid)

    def judge(self) -> list[Finding]:
        """Return findings ranked by severity desc, then confidence desc."""
        ranked = sorted(
            self._by_signature.values(),
            key=lambda f: (
                -_SEVERITY_ORDER[f.severity],
                -[Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH].index(f.confidence),
            ),
        )
        return ranked

    @property
    def findings(self) -> list[Finding]:
        return self.judge()

    def __len__(self) -> int:
        return len(self._by_signature)
