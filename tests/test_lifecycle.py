"""Tests for hardened evidence/finding lifecycle + scan lifecycle."""

from core.evidence.models import make_evidence
from core.findings.engine import FindingEngine
from core.findings.models import (
    EvidenceLocation,
    EvidenceLocationKind,
    FindingStatus,
    Severity,
)
from core.orchestrator.scan_status import ScanStatus


def _ev(eid, target="api.example.com"):
    return make_evidence("scn_1", "trun_1", "nuclei", target, '{"a":1}', evidence_id=eid)


def test_candidate_not_auto_confirmed():
    eng = FindingEngine()
    f = eng.add_candidate("XSS", Severity.HIGH, root_cause="r")
    assert f.status == FindingStatus.CANDIDATE  # hypothesis, not confirmed


def test_lifecycle_advances_explicitly():
    eng = FindingEngine()
    f = eng.add_candidate("XSS", Severity.HIGH, root_cause="r")
    eng.analyze(f)
    assert f.status == FindingStatus.ANALYZED
    eng.validate(f)
    assert f.status == FindingStatus.VALIDATED
    eng.confirm(f)
    assert f.status == FindingStatus.CONFIRMED


def test_reject_marks_false_positive():
    eng = FindingEngine()
    f = eng.add_candidate("False positive", Severity.HIGH, root_cause="r")
    eng.reject(f)
    assert f.status == FindingStatus.REJECTED
    # rejected findings are excluded from judge() by default
    assert eng.judge() == []
    assert len(eng.judge(include_rejected=True)) == 1


def test_correlation_exact_target_match():
    eng = FindingEngine()
    f = eng.add_candidate("leak", Severity.HIGH, affected_component="api.example.com", root_cause="r")
    ev = _ev("ev1", target="api.example.com")
    eng.correlate([ev])
    assert "ev1" in f.evidence


def test_correlation_no_substring_false_positive():
    """'api.example.com' must NOT match a finding about 'example.com' via substring."""
    eng = FindingEngine()
    f = eng.add_candidate("leak", Severity.HIGH, affected_component="example.com", root_cause="r")
    ev = _ev("ev1", target="api.example.com")
    eng.correlate([ev])
    assert "ev1" not in f.evidence  # exact match required


def test_correlation_by_structured_location():
    eng = FindingEngine()
    loc = EvidenceLocation(kind=EvidenceLocationKind.FILE, value="src/App.js")
    f = eng.add_candidate("xss", Severity.HIGH, root_cause="r", locations=[loc])
    ev = _ev("ev1", target="src/App.js")
    eng.correlate([ev])
    assert "ev1" in f.evidence


def test_signature_includes_locations():
    a = EvidenceLocation(kind=EvidenceLocationKind.FILE, value="a.js")
    b = EvidenceLocation(kind=EvidenceLocationKind.FILE, value="b.js")
    f1 = __import__("core.findings.models", fromlist=["make_finding"]).make_finding(
        "x", Severity.HIGH, root_cause="r", locations=[a])
    f2 = __import__("core.findings.models", fromlist=["make_finding"]).make_finding(
        "x", Severity.HIGH, root_cause="r", locations=[b])
    assert f1.signature() != f2.signature()  # different locations -> different sig


def test_scan_status_terminal():
    assert ScanStatus.QUEUED.terminal is False
    assert ScanStatus.RUNNING.terminal is False
    for s in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.PARTIAL,
              ScanStatus.CANCELLED, ScanStatus.TIMEOUT]:
        assert s.terminal is True
