"""Finding Engine (hardened): correlation, dedup, validation, judge.

The real lifecycle:

    ToolRun -> Artifact -> Evidence -> Correlation -> Validation/Judge -> Finding

This engine implements the correlation + judge stages. Key properties:

- Evidence produced by a tool run is available here BEFORE findings persist.
- ``add_candidate`` creates a Finding with status CANDIDATE (a hypothesis).
  It is NOT automatically a final finding.
- Correlation matches evidence to findings via structured locations
  (EvidenceLocation) or exact component/target equality — never naive substring
  matching alone.
- Judge ranks candidates by severity + confidence. A judge/human can mark a
  candidate REJECTED (false positive).
"""
from __future__ import annotations

from ..evidence.models import Evidence
from .models import (
    Confidence,
    EvidenceLocation,
    Finding,
    FindingStatus,
    Severity,
    make_finding,
)

_SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 1,
}

_CONFIDENCE_ORDER = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]


class FindingEngine:
    def __init__(self) -> None:
        self._by_signature: dict[str, Finding] = {}
        self._evidence_of: dict[str, list[str]] = {}

    # ---- Candidate ingestion ----
    def add_candidate(
        self,
        title: str,
        severity: Severity,
        affected_component: str = "",
        root_cause: str = "",
        confidence: Confidence = Confidence.LOW,
        evidence_ids: list[str] | None = None,
        locations: list[EvidenceLocation] | None = None,
    ) -> Finding:
        """Add a candidate (hypothesis); dedup by signature. Status = CANDIDATE.

        This NEVER produces a confirmed finding. The caller must explicitly
        validate/confirm (or reject) via the lifecycle methods.
        """
        probe = make_finding(
            title, severity, affected_component, root_cause, confidence,
            evidence=evidence_ids, locations=locations,
        )
        sig = probe.signature()

        existing = self._by_signature.get(sig)
        if existing is None:
            existing = probe
            self._by_signature[sig] = existing
            self._evidence_of[sig] = []
        else:
            # Merge: keep the higher severity/confidence; union evidence/locations.
            existing.severity = max(existing.severity, severity, key=lambda s: _SEVERITY_ORDER[s])
            existing.confidence = max(
                existing.confidence, confidence,
                key=lambda c: _CONFIDENCE_ORDER.index(c),
            )
            for loc in locations or []:
                if loc not in existing.locations:
                    existing.locations.append(loc)

        for ev in evidence_ids or []:
            if ev not in existing.evidence:
                existing.evidence.append(ev)
            if ev not in self._evidence_of[sig]:
                self._evidence_of[sig].append(ev)

        return existing

    # ---- Correlation ----
    def correlate(self, evidence: list[Evidence]) -> None:
        """Attach evidence to findings.

        Matching rules (no naive substring matching on target alone):
        1. Exact equality between evidence.target and finding.affected_component.
        2. Structured location match: evidence locations/keys match the
           finding's locations (e.g. file:src/App.js == finding file location).
        """
        evidence_by_target: dict[str, list[str]] = {}
        for ev in evidence:
            evidence_by_target.setdefault(ev.target, []).append(ev.id)

        for sig, finding in self._by_signature.items():
            for target, ev_ids in evidence_by_target.items():
                if target and finding.affected_component and target == finding.affected_component:
                    self._attach(sig, finding, ev_ids)

            # structured location match: finding locations vs evidence target
            for loc in finding.locations:
                if loc.value and loc.value in evidence_by_target:
                    self._attach(sig, finding, evidence_by_target[loc.value])

    def _attach(self, sig: str, finding: Finding, ev_ids: list[str]) -> None:
        for eid in ev_ids:
            if eid not in finding.evidence:
                finding.evidence.append(eid)
            if eid not in self._evidence_of[sig]:
                self._evidence_of[sig].append(eid)

    # ---- Lifecycle transitions ----
    def analyze(self, finding: Finding) -> Finding:
        if finding.status == FindingStatus.CANDIDATE:
            finding.status = FindingStatus.ANALYZED
        return finding

    def validate(self, finding: Finding) -> Finding:
        if finding.status in (FindingStatus.CANDIDATE, FindingStatus.ANALYZED):
            finding.status = FindingStatus.VALIDATED
        return finding

    def confirm(self, finding: Finding) -> Finding:
        if finding.status in (FindingStatus.CANDIDATE, FindingStatus.ANALYZED, FindingStatus.VALIDATED):
            finding.status = FindingStatus.CONFIRMED
        return finding

    def reject(self, finding: Finding) -> Finding:
        """Mark a candidate/finding as a false positive."""
        finding.status = FindingStatus.REJECTED
        return finding

    # ---- Judge ----
    def judge(self, include_rejected: bool = False) -> list[Finding]:
        """Return findings ranked by severity desc, then confidence desc.

        REJECTED findings are excluded by default (they are false positives,
        not actionable). Pass include_rejected=True to include them.
        """
        ranked = sorted(
            self._by_signature.values(),
            key=lambda f: (
                -_SEVERITY_ORDER[f.severity],
                -_CONFIDENCE_ORDER.index(f.confidence),
            ),
        )
        if not include_rejected:
            ranked = [f for f in ranked if f.status != FindingStatus.REJECTED]
        return ranked

    @property
    def findings(self) -> list[Finding]:
        return self.judge()

    def __len__(self) -> int:
        return len(self._by_signature)
