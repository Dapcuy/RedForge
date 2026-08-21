"""Tests for the `redforge scan` CLI workflow (orchestrated scan)."""
import json
import os
import subprocess
from pathlib import Path

TOOLS_DIR = Path(__file__).parent.parent / "tools"
FIXTURE = Path(__file__).parent / "fixtures" / "vuln_app"


def _run_scan(args: list[str], timeout: int = 60) -> dict:
    """Run `python -m core scan ...` and parse the JSON output."""
    proc = subprocess.run(
        [os.sys.executable, "-m", "core", "scan", *args],
        capture_output=True, text=True, timeout=timeout, cwd=Path(__file__).parent.parent,
    )
    assert proc.returncode in (0, 1), f"scan failed: {proc.stderr[:500]}"
    return json.loads(proc.stdout)


def test_scan_source_dir_without_agent_dry_run(tmp_path):
    """--no-agent: profile + skill resolution only, no findings."""
    out = _run_scan(["--target", str(FIXTURE), "--kind", "source-dir", "--no-agent"])
    assert out["status"] == "completed"
    assert out["scan_id"].startswith("scn_")
    assert out["findings"] == []


def test_scan_source_dir_with_agent_generates_candidates():
    """Default agent (CodeAgent) detects patterns -> candidate findings."""
    out = _run_scan(["--target", str(FIXTURE), "--kind", "source-dir"])
    # Tool execution may fail without Docker images, but the agent candidates
    # must still be produced and the scan must not crash.
    assert out["status"] in ("completed", "partial")
    titles = [f["title"] for f in out["findings"]]
    assert any("eval" in t for t in titles), f"no eval finding in {titles}"
    assert all(f["status"] == "candidate" for f in out["findings"])


def test_scan_external_url_denied_by_default():
    """Fail-closed: external URL is out of scope under the default policy."""
    out = _run_scan(["--target", "http://example.com", "--kind", "url", "--no-agent"])
    # The orchestrator catches policy violation -> FAILED status with error.
    assert out["status"] == "failed"
    assert "out of scope" in out["error"] or "external" in out["error"].lower()


def test_scan_local_url_profile_runs(tmp_path):
    """Local URL target passes scope and is profiled (may fail at tool exec)."""
    out = _run_scan(["--target", "http://127.0.0.1:9", "--kind", "url"], timeout=45)
    # 127.0.0.1 is local -> allowed; tool exec may fail (no image) but the scan
    # must not crash and must report a valid status.
    assert out["status"] in ("completed", "partial", "failed")
    assert out["scan_id"].startswith("scn_")
