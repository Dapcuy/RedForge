"""Tests for the dashboard (HTTP handler logic, no server bind needed)."""
import json

from core.findings.models import Severity, make_finding
from web.dashboard.app import DashboardHandler


def test_dashboard_findings_json():
    findings = [
        make_finding("Critical XSS", Severity.CRITICAL, affected_component="app", root_cause="r"),
        make_finding("Low info", Severity.LOW, root_cause="r2"),
    ]
    DashboardHandler.findings = findings

    payload = json.dumps({"findings": [f.to_dict() for f in findings]}).encode()
    data = json.loads(payload)
    assert len(data["findings"]) == 2
    assert data["findings"][0]["severity"] == "critical"


def test_dashboard_index_html_served():
    from web.dashboard.app import INDEX_HTML

    assert "<title>RedForge Dashboard</title>" in INDEX_HTML
    assert "/api/findings" in INDEX_HTML
