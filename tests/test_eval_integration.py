"""Integration: evaluation harness against a real `redforge scan` (no Docker needed for structure).

This asserts the harness reads real pipeline output and produces structured
metrics. It does NOT assert high detection (agent-only candidates are not
auto-validated yet — a known, documented gap).
"""
import subprocess
import sys
import tempfile
from pathlib import Path

from evaluation.metrics import load_benchmark, score_benchmark

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "vuln_app"
BENCH = ROOT / "evaluation" / "benchmarks" / "semgrep_vuln_app.json"


def test_eval_harness_integration_with_scan():
    """`redforge scan` -> SQLite -> harness reads findings -> metrics structure."""
    tmp = tempfile.mkdtemp(prefix="redforge-eval-it-")
    db = str(Path(tmp) / "scan.db")
    cmd = [sys.executable, "-m", "core", "scan", "--target", str(FIXTURE),
           "--kind", "source-dir", "--db", db]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=ROOT)
    assert proc.returncode in (0, 1), f"scan failed: {proc.stderr[:500]}"

    import sqlite3
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    findings = [dict(r) for r in con.execute(
        "SELECT title, severity, status, affected_component FROM findings"
    )]
    con.close()
    assert findings, "scan produced no findings rows"

    bench = load_benchmark(BENCH)
    res = score_benchmark(bench, findings)
    d = res.to_dict()
    # Structure correctness.
    for key in ("detection_rate", "precision", "recall", "false_positive_rate",
                "validation_rate", "dedup_rate", "tool_success_rate"):
        assert key in d and isinstance(d[key], (int, float))
    # Agent-only candidates: not confirmed yet (documented gap) — assert the
    # metric is 0 rather than silently assuming validation.
    assert res.confirmed == 0
    assert res.detection_rate == 0.0
