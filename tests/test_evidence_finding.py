"""Tests for evidence + finding engine (dedup, correlation, judge)."""
from core.evidence.models import EvidenceType, make_evidence
from core.evidence.normalizer import normalize_evidence
from core.findings.engine import FindingEngine
from core.findings.models import Confidence, FindingStatus, Severity


def _ev(tool, target, raw, eid=None):
    return make_evidence("r1", tool, target, raw, evidence_id=eid)


def test_evidence_digest_stable():
    e = _ev("nuclei", "https://x", "hello")
    assert e.digest == e.digest
    assert e.type == EvidenceType.HTTP


def test_evidence_type_mapping():
    assert _ev("semgrep", "x", "r").type == EvidenceType.CODE
    assert _ev("slither", "x", "r").type == EvidenceType.SMART_CONTRACT
    assert _ev("unknown-tool", "x", "r").type == EvidenceType.GENERIC


def test_normalize_http_json():
    e = _ev("nuclei", "https://x", '[{"template-id": "cve-2024"}]')
    normalize_evidence(e)
    assert e.normalized is not None
    assert len(e.normalized["results"]) == 1


def test_normalize_generic_leaves_none():
    e = _ev("unknown-tool", "x", "raw text")
    normalize_evidence(e)
    assert e.normalized is None


def test_finding_dedup_by_root_cause():
    eng = FindingEngine()
    f1 = eng.add_candidate(
        "SQLi in login", Severity.HIGH, affected_component="login", root_cause="unsanitized input"
    )
    f2 = eng.add_candidate(
        "SQL injection on auth", Severity.CRITICAL, affected_component="login", root_cause="unsanitized input"
    )
    # same signature -> deduped to one finding
    assert len(eng) == 1
    assert f1.id == f2.id
    # severity promoted to the max
    assert f1.severity == Severity.CRITICAL


def test_finding_distinct_root_causes_not_deduped():
    eng = FindingEngine()
    eng.add_candidate("a", Severity.HIGH, affected_component="x", root_cause="cause-a")
    eng.add_candidate("b", Severity.HIGH, affected_component="x", root_cause="cause-b")
    assert len(eng) == 2


def test_judge_orders_by_severity():
    eng = FindingEngine()
    eng.add_candidate("low", Severity.LOW, root_cause="r1")
    eng.add_candidate("critical", Severity.CRITICAL, root_cause="r2")
    eng.add_candidate("medium", Severity.MEDIUM, root_cause="r3")
    ranked = eng.judge()
    assert ranked[0].severity == Severity.CRITICAL
    assert ranked[-1].severity == Severity.LOW


def test_correlation_links_evidence():
    eng = FindingEngine()
    f = eng.add_candidate(
        "leak", Severity.HIGH, affected_component="api.example.com", root_cause="r"
    )
    ev = _ev("nuclei", "api.example.com", "{}", eid="ev1")
    eng.correlate([ev])
    assert "ev1" in f.evidence


def test_lifecycle_transitions():
    eng = FindingEngine()
    f = eng.add_candidate("x", Severity.HIGH, root_cause="r")
    assert f.status == FindingStatus.CANDIDATE
    f.status = FindingStatus.ANALYZED
    f.status = FindingStatus.VALIDATED
    f.status = FindingStatus.CONFIRMED
    assert f.status == FindingStatus.CONFIRMED
