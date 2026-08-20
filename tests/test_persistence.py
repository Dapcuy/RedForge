"""Tests for the persistence layer (SQLite backend + BlobStore)."""

import pytest

from core.evidence.models import EvidenceType, make_evidence
from core.execution.models import Artifact, ExecutionContext, ToolRun
from core.findings.models import Severity, make_finding
from core.models import RunStatus
from core.persistence.store import BlobStore, SqliteStore


@pytest.fixture
def store(tmp_path):
    blob = BlobStore(str(tmp_path / "blobs"))
    db = SqliteStore(str(tmp_path / "redforge.db"), blob_store=blob)
    yield db
    db.close()


def test_project_roundtrip(store):
    store.add_project("prj_1", "my project", {"owner": "me"})
    assert store.get_project("prj_1")["name"] == "my project"
    assert len(store.list_projects()) == 1


def test_target_and_scan_roundtrip(store):
    store.add_target("tgt_1", "prj_1", "url", "https://x")
    store.add_scan("scn_1", "prj_1", "tgt_1", "running")
    assert store.get_target("tgt_1")["value"] == "https://x"
    assert store.get_scan("scn_1")["status"] == "running"


def test_tool_run_roundtrip(store):
    run = ToolRun(
        id="trun_1", tool_name="nuclei", tool_version="3.3.0", capability="vuln-scan",
        target="https://x", context=ExecutionContext("prj", "tgt", "scn"),
        command=["docker", "run", "nuclei"], runtime="docker",
        status=RunStatus.SUCCESS, exit_code=0, stdout="out", stderr="",
    )
    store.add_tool_run(run)
    got = store.get_tool_run("trun_1")
    assert got.tool_name == "nuclei"
    assert got.status == RunStatus.SUCCESS
    assert got.context.scan_id == "scn"


def test_artifact_roundtrip(store):
    a = Artifact(id="art_1", tool_run_id="trun_1", kind="stdout", format="text", content="hello")
    store.add_artifact(a)
    got = store.get_artifact("art_1")
    assert got.content == "hello"
    assert got.kind == "stdout"


def test_evidence_roundtrip(store):
    ev = make_evidence("scn_1", "trun_1", "nuclei", "https://x", '{"a":1}', tool_version="3.3.0")
    store.add_evidence(ev)
    got = store.get_evidence(ev.id)
    assert got.tool == "nuclei"
    assert got.tool_version == "3.3.0"
    assert got.type == EvidenceType.HTTP
    assert got.digest == ev.digest


def test_finding_roundtrip(store):
    f = make_finding("SQLi", Severity.HIGH, affected_component="login", root_cause="r")
    store.add_finding(f)
    got = store.get_finding(f.id)
    assert got.title == "SQLi"
    assert got.severity == Severity.HIGH


def test_large_artifact_externalized(tmp_path):
    blob = BlobStore(str(tmp_path / "blobs"), threshold_bytes=10)
    db = SqliteStore(str(tmp_path / "redforge.db"), blob_store=blob)

    big = "x" * 5000
    a = Artifact(id="art_big", tool_run_id="trun_1", kind="stdout", format="text", content=big)
    db.add_artifact(a)
    got = db.get_artifact("art_big")
    # content was externalized: path is set, content emptied, hash recorded
    assert got.path != ""
    assert got.content == ""
    assert got.sha256 != ""
    # the blob is recoverable
    assert blob.get(got.path) == big
    db.close()


def test_blob_store_content_addressed(tmp_path):
    blob = BlobStore(str(tmp_path / "blobs"))
    digest1, path1, size1 = blob.put("hello")
    digest2, path2, size2 = blob.put("hello")
    assert digest1 == digest2
    assert path1 == path2
    assert size1 == size2 == 5
