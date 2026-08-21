"""REAL Docker E2E: source-code security scan with the actual Semgrep binary.

This test proves the production-like vertical slice:

    host/tests/fixtures/vuln_app/app.py
        -> mounted as container:/workspace/app.py (read-only)
        -> semgrep /workspace (real binary, pinned version)
        -> Artifact -> Evidence -> Finding -> SQLite

It is intentionally separated from unit/integration tests (which use
FakeRuntime) and from the tiny e2e-probe test (which uses a trivial image).
This test uses the REAL code-runtime image and the REAL semgrep binary.

Skipped automatically when no Docker daemon is available.
"""
import json
import subprocess
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

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "vuln_app"
TOOLS_DIR = Path(__file__).parent.parent / "tools"

# Must match tools/semgrep.tool.yaml and runtimes/code/Dockerfile.
EXPECTED_SEMGREP_VERSION = "1.95.0"
IMAGE = "redforge/code-runtime:latest"


def _docker_available() -> bool:
    try:
        proc = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=10)
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = [
    pytest.mark.skipif(not _docker_available(), reason="Docker daemon not available"),
    pytest.mark.docker_e2e,
]


@pytest.fixture(scope="module")
def code_runtime():
    return DockerRuntime()


@pytest.fixture(scope="module")
def registry():
    reg = ToolRegistry()
    reg.load_dir(str(TOOLS_DIR))
    return reg


def _request(registry, run_suffix: str):
    """A ToolRequest for the semgrep tool against the vulnerable fixture."""
    semgrep = registry.get("semgrep")
    assert semgrep is not None, "semgrep manifest not loaded"
    # Fail early if the manifest version drifts from the image.
    assert semgrep.runtime.get("version") == EXPECTED_SEMGREP_VERSION, (
        f"semgrep manifest version {semgrep.runtime.get('version')} != expected {EXPECTED_SEMGREP_VERSION}"
    )
    return ToolRequest(
        id=tool_request_id("semgrep", run_suffix),
        capability="source-scanning",
        tool_name="semgrep",
        target=Target(TargetKind.SOURCE_DIR, str(FIXTURE_DIR)),
        context=ExecutionContext(
            project_id="prj_semgrep_e2e",
            target_id=target_id(str(FIXTURE_DIR)),
            scan_id=scan_id("semgrep", run_suffix),
        ),
        arguments={
            "path": ".",                    # remapped to /workspace by the execution service
            "json": True,
            "config": "semgrep-rules.yml",  # local rules inside the workspace (offline, deterministic)
        },
    )


def test_real_semgrep_scan_end_to_end(tmp_path, code_runtime, registry):
    """The full acceptance flow: mount -> semgrep -> artifact -> evidence -> finding -> SQLite."""
    # --- Persistence ---
    blob = BlobStore(str(tmp_path / "blobs"))
    db = SqliteStore(str(tmp_path / "redforge.db"), blob_store=blob)

    policy = Policy(per_tool_limits={"semgrep": {"timeout_s": 300, "memory_mb": 1024}})
    workspaces = AuthorizedWorkspaceRegistry()
    wid = workspaces.register(str(FIXTURE_DIR), label="semgrep").id
    svc = ToolExecutionService(registry, code_runtime, PolicyEngine(policy), workspaces=workspaces)

    request = _request(registry, "real")
    request.workspace_id = wid
    outcome = svc.execute(request)
    run = outcome.tool_run

    # --- 1. ToolRun: real container execution, exit 0, real output ---
    assert run.status.value == "success", f"semgrep failed: {run.stderr[:500]}"
    assert run.exit_code == 0
    assert run.runtime == "docker"
    assert run.tool_name == "semgrep"
    assert run.tool_version == EXPECTED_SEMGREP_VERSION

    # --- 2. Workspace mounted: command must mount host fixture -> /workspace:ro,
    # and semgrep must scan /workspace (not a copied tree). ---
    cmd = run.command
    fixture_ro = f"{str(FIXTURE_DIR).replace(chr(92), '/')}:/workspace:ro"
    assert any(fixture_ro in c for c in cmd), f"workspace not mounted ro: {cmd}"
    # semgrep entrypoint + /workspace as the scan target (path may be /workspace or /workspace/)
    assert any("/workspace" in c and "semgrep" in c for c in cmd), f"semgrep not scanning /workspace: {cmd}"
    scan_targets = [c for c in cmd if c.startswith("/workspace")]
    assert scan_targets, f"no /workspace scan target in: {cmd}"
    assert scan_targets[0].rstrip("/") == "/workspace"

    # --- 3. Real artifact produced ---
    stdout_artifacts = [a for a in outcome.artifacts if a.kind == "stdout"]
    assert stdout_artifacts, "no stdout artifact produced"
    artifact = stdout_artifacts[0]
    assert artifact.content, "artifact has no content"

    # --- 4. Semgrep result is real JSON with findings ---
    try:
        semgrep_json = json.loads(artifact.content)
    except json.JSONDecodeError as exc:
        pytest.fail(f"semgrep output is not JSON: {exc}\n{artifact.content[:800]}")
    assert "results" in semgrep_json
    real_results = semgrep_json["results"]
    assert real_results, "semgrep produced zero results against the vulnerable fixture"
    assert semgrep_json["errors"] == [], f"semgrep errors: {semgrep_json['errors'][:3]}"

    # --- 5. Evidence created + normalized + persisted ---
    ev = make_evidence(
        scan_id=request.context.scan_id,
        tool_run_id=run.id,
        tool=run.tool_name,
        target=run.target,
        raw=artifact.content,
        raw_format="json",
        tool_version=run.tool_version,
        source="semgrep",
        artifact_id=artifact.id,
    )
    normalize_evidence(ev)
    assert ev.normalized is not None
    assert len(ev.normalized.get("results", [])) >= 1
    db.add_evidence(ev)

    # --- 6. Finding engine: correlation -> candidate -> validate/confirm ---
    engine = FindingEngine()
    first = real_results[0]
    loc = EvidenceLocation(kind=EvidenceLocationKind.FILE, value=first.get("path", ""))
    line = EvidenceLocation(kind=EvidenceLocationKind.LINE, value=str(first.get("start", {}).get("line", "")))
    finding = engine.add_candidate(
        title=f"Semgrep: {first.get('check_id', 'finding')}",
        severity=Severity.HIGH,
        affected_component=first.get("path", run.target),
        root_cause=first.get("extra", {}).get("message", "")[:200],
        evidence_ids=[ev.id],
        locations=[loc, line],
    )
    assert finding.status.value == "candidate"  # hypothesis, not auto-confirmed
    engine.validate(finding)
    engine.confirm(finding)
    assert finding.status.value == "confirmed"

    # --- 7. Persist ToolRun + Artifacts + Finding ---
    db.add_tool_run(run)
    for a in outcome.artifacts:
        db.add_artifact(a)
    db.add_finding(finding)

    # --- 8. SQLite persistence verification ---
    assert db.get_tool_run(run.id) is not None
    assert db.get_artifact(artifact.id) is not None
    assert db.get_evidence(ev.id) is not None
    assert db.get_finding(finding.id) is not None
    persisted = db.get_finding(finding.id)
    assert persisted.status.value == "confirmed"
    assert ev.id in persisted.evidence
    assert len(persisted.locations) >= 1

    # Provenance chain intact
    assert ev.id == db.get_evidence(ev.id).id
    assert db.get_artifact(artifact.id).tool_run_id == run.id
    assert ev.id in persisted.evidence
    db.close()
