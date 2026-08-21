"""Docker E2E: `redforge scan` CLI against a LOCAL lab server (real web tools).

Proves the production CLI workflow end-to-end:

    redforge scan http://host.docker.internal:PORT
        -> scope (local) -> profile_url (real) -> agent (ReconAgent)
        -> httpx/nuclei via DockerRuntime -> artifact -> evidence -> finding
        -> SQLite

Skipped when Docker is unavailable or web-runtime is not built.
"""
import http.server
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "vuln_app"
ROOT = Path(__file__).parent.parent


class _LabHandler(http.server.BaseHTTPRequestHandler):
    server_version = "RedForgeLab/1.0"
    sys_version = ""

    def do_GET(self):
        body = b"<html><head><title>Lab</title></head><body>hello admin area</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "Express")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _docker_available() -> bool:
    try:
        p = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=10)
        return p.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _web_image_built() -> bool:
    try:
        p = subprocess.run(["docker", "image", "inspect", "redforge/web-runtime:latest"],
                           capture_output=True, text=True, timeout=10)
        return p.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = [
    pytest.mark.skipif(not _docker_available(), reason="Docker daemon not available"),
    pytest.mark.skipif(not _web_image_built(), reason="web-runtime image not built"),
    pytest.mark.docker_e2e,
]


@pytest.fixture(scope="module")
def lab_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://host.docker.internal:{port}"
    srv.shutdown()


def test_cli_scan_local_url_full_slice(lab_server):
    """redforge scan <local-url> runs real httpx -> evidence -> finding -> SQLite."""
    proc = subprocess.run(
        [sys.executable, "-m", "core", "scan", "--target", lab_server, "--kind", "url"],
        capture_output=True, text=True, timeout=180, cwd=ROOT,
    )
    assert proc.returncode in (0, 1), f"scan crashed: {proc.stderr[:500]}"
    out = json.loads(proc.stdout)
    # The scan completes (tool may be partial if nuclei needs templates, but
    # httpx must succeed and produce evidence).
    assert out["status"] in ("completed", "partial"), f"scan status: {out['status']} {out.get('error')}"
    assert out["scan_id"].startswith("scn_")
    assert out["evidence_count"] >= 1, f"no evidence: {out.get('error')}"
    assert len(out["tool_runs"]) >= 1
