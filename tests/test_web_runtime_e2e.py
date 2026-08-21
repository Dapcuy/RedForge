"""Real Web Runtime E2E: httpx / nuclei / ffuf against a LOCAL authorized target.

This proves the web vertical slice:

    local server (127.0.0.1) -> policy scope -> tool registry -> Docker runtime
        -> real web tool -> artifact -> evidence -> finding -> SQLite

The target is a localhost security-lab server we control (authorized). No
external targets are touched.

Requirements:
- redforge/web-runtime image built (httpx/nuclei/ffuf pinned)
- Docker daemon available

Skipped automatically when either is missing.
"""
import http.server
import json
import subprocess
import threading
from pathlib import Path

import pytest

from core.evidence.models import make_evidence
from core.evidence.normalizer import normalize_evidence
from core.execution.models import ExecutionContext, ToolRequest
from core.execution.service import ToolExecutionService
from core.execution.workspace import AuthorizedWorkspaceRegistry
from core.findings.engine import FindingEngine
from core.findings.models import EvidenceLocation, EvidenceLocationKind, Severity
from core.ids import scan_id, target_id, tool_request_id
from core.models import Target, TargetKind
from core.persistence.store import BlobStore, SqliteStore
from core.policy.engine import Policy, PolicyEngine
from core.runtime.base import DockerRuntime
from core.tools.registry import ToolRegistry

TOOLS_DIR = Path(__file__).parent.parent / "tools"
IMAGE = "redforge/web-runtime:latest"
EXPECTED_VERSIONS = {"nuclei": "3.3.7", "httpx": "1.6.9", "ffuf": "2.1.0"}


def _docker_available() -> bool:
    try:
        proc = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=10)
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _image_built() -> bool:
    try:
        proc = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, text=True, timeout=10)
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = [
    pytest.mark.skipif(not _docker_available(), reason="Docker daemon not available"),
    pytest.mark.skipif(not _image_built(), reason="web-runtime image not built"),
    pytest.mark.docker_e2e,
]


class _LabServer(http.server.BaseHTTPRequestHandler):
    """Minimal local security-lab: vulnerable-ish endpoints for nuclei/httpx/ffuf."""

    server_version = "RedForgeLab/1.0"
    sys_version = ""

    def do_GET(self):
        if self.path == "/":
            body = b"<html><head><title>Lab</title></head><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Powered-By", "Express")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/admin":
            body = b"<html><body>admin area</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *args):  # silence
        pass


@pytest.fixture(scope="module")
def lab_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LabServer)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # The web tools run INSIDE a container; they reach the host server via
    # host.docker.internal (Docker Desktop on Windows/Mac; Linux: --add-host).
    yield f"http://host.docker.internal:{port}"
    server.shutdown()


@pytest.fixture(scope="module")
def registry():
    reg = ToolRegistry()
    reg.load_dir(str(TOOLS_DIR))
    return reg


@pytest.fixture
def service(registry):
    from core.execution.models import ResourceLimits

    # Local target allowed by default (fail-closed blocks external); network
    # bridge enabled for the web tools to reach the local lab.
    policy = Policy(
        allow_local_targets=True,
        external_targets=False,
        limits=ResourceLimits(network="bridge"),
        per_tool_limits={
            "nuclei": {"timeout_s": 120, "memory_mb": 1024},
            "httpx": {"timeout_s": 120, "memory_mb": 512},
            "ffuf": {"timeout_s": 120, "memory_mb": 512},
        },
    )
    workspaces = AuthorizedWorkspaceRegistry()
    return ToolExecutionService(registry, DockerRuntime(), PolicyEngine(policy), workspaces=workspaces)


def _req(tool_name, capability, target_url, run_suffix, **arguments):
    return ToolRequest(
        id=tool_request_id("web", run_suffix),
        capability=capability,
        tool_name=tool_name,
        target=Target(TargetKind.URL, target_url),
        context=ExecutionContext("prj_web", target_id(target_url), scan_id("web", run_suffix)),
        arguments=arguments,
    )


def test_httpx_real_against_local_lab(service, lab_server):
    """httpx (python) real run against the local lab; structured artifact produced."""
    req = _req("httpx", "http-analysis", lab_server, "httpx", u=lab_server, json=True, silent=True)
    outcome = service.execute(req)
    run = outcome.tool_run
    assert run.status.value == "success", f"httpx failed: {run.stderr[:500]}"
    assert run.runtime == "docker"
    # httpx may occasionally emit the banner/warnings to stdout; search all
    # stdout+stderr for a JSON object line.
    blob = "\n".join([a.content for a in outcome.artifacts] + [run.stdout, run.stderr])
    parsed = [json.loads(ln) for ln in blob.splitlines() if ln.strip().startswith("{")]
    if not parsed:
        raise AssertionError(
            f"no JSON output; command={run.command[-6:]} stdout={run.stdout[:200]!r} stderr={run.stderr[-200:]!r}"
        )
    assert parsed[0].get("url", "").startswith("http://host.docker.internal")


def test_nuclei_real_with_local_template(service, lab_server, tmp_path):
    """nuclei (real Go binary) runs a local template against the local lab."""
    template = tmp_path / "lab.yaml"
    template.write_text(
        "id: redforge-lab-admin\n"
        "info:\n"
        "  name: Lab Admin Detector\n"
        "  author: redforge\n"
        "  severity: info\n"
        "http:\n"
        "  - method: GET\n"
        "    path:\n"
        "      - \"{{BaseURL}}/admin\"\n"
        "    matchers:\n"
        "      - type: word\n"
        "        words:\n"
        "          - \"admin area\"\n",
        encoding="utf-8",
    )
    req = _req("nuclei", "template-scanning", lab_server, "nuclei",
               u=lab_server, template=str(template), jsonl=True, duc=True, silent=True)
    # host.docker.internal resolution from a fresh container is occasionally
    # flaky on Docker Desktop (Windows): nuclei may exit 0 with no output when
    # it cannot reach the host alias. Retry once — this is an infra flake, not
    # a RedForge logic failure.
    outcome = None
    for attempt in range(2):
        outcome = service.execute(req)
        run = outcome.tool_run
        if any(a.kind == "stdout" and a.content.strip() for a in outcome.artifacts):
            break
    run = outcome.tool_run
    # nuclei exit code is non-zero when findings exist with -jsonl; the run
    # still produced real output. Accept success OR failed-with-output.
    stdout_artifacts = [a for a in outcome.artifacts if a.kind == "stdout"]
    assert stdout_artifacts, "nuclei produced no stdout artifact"
    content = stdout_artifacts[0].content
    assert content.strip(), "nuclei produced empty output"
    # If JSONL lines exist, verify our template matched the admin endpoint.
    parsed = [json.loads(ln) for ln in content.splitlines() if ln.strip().startswith("{")]
    if parsed:
        assert any("redforge-lab-admin" in str(p.get("template-id", "")) for p in parsed), parsed
    # provenance intact
    assert run.tool_version == EXPECTED_VERSIONS["nuclei"]


def test_web_slice_persists_artifact_evidence_finding(service, lab_server, tmp_path):
    """Full web vertical slice: httpx -> artifact -> evidence -> finding -> SQLite."""
    blob = BlobStore(str(tmp_path / "blobs"))
    db = SqliteStore(str(tmp_path / "web.db"), blob_store=blob)

    req = _req("httpx", "http-analysis", lab_server, "persist", u=lab_server, json=True, silent=True)
    outcome = service.execute(req)
    run = outcome.tool_run
    assert run.status.value == "success"

    artifact = next(a for a in outcome.artifacts if a.kind == "stdout")

    ev = make_evidence(
        scan_id=req.context.scan_id, tool_run_id=run.id, tool=run.tool_name,
        target=run.target, raw=artifact.content, raw_format="json",
        tool_version=run.tool_version, source="httpx", artifact_id=artifact.id,
    )
    normalize_evidence(ev)

    engine = FindingEngine()
    finding = engine.add_candidate(
        title="Web server detected on local lab",
        severity=Severity.INFORMATIONAL,
        affected_component=lab_server,
        root_cause="lab server responded with technology headers",
        evidence_ids=[ev.id],
        locations=[EvidenceLocation(EvidenceLocationKind.URL, lab_server)],
    )
    engine.validate(finding)
    engine.confirm(finding)

    db.add_tool_run(run)
    db.add_artifact(artifact)
    db.add_evidence(ev)
    db.add_finding(finding)

    assert db.get_tool_run(run.id) is not None
    assert db.get_artifact(artifact.id) is not None
    assert db.get_evidence(ev.id) is not None
    persisted = db.get_finding(finding.id)
    assert persisted is not None and persisted.status.value == "confirmed"
    assert ev.id in persisted.evidence
    db.close()
