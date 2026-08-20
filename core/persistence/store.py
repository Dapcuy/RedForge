"""SQLite backend + on-disk BlobStore for large artifacts.

- ``SqliteStore`` implements all repository Protocols over a single SQLite DB.
- ``BlobStore`` stores large raw payloads on disk, content-addressed by sha256,
  so big outputs never bloat the database — the DB only holds a reference
  (path + hash + size).

The core never imports sqlite3; it depends only on the Protocols. This module
is the first (and currently only) backend implementation.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from typing import Literal

from ..evidence.models import Evidence, EvidenceType
from ..execution.models import Artifact, ToolRun
from ..findings.models import (
    Confidence,
    EvidenceLocation,
    EvidenceLocationKind,
    Finding,
    FindingStatus,
    Severity,
)


class _Transaction:
    """A unit-of-work context manager over a SQLite connection.

    Repository methods commit after each write by default (simple, safe). When
    a transaction is active, the store sets ``_in_transaction`` so those
    per-write commits become no-ops; the transaction issues a single
    COMMIT/ROLLBACK on exit. Nested transactions are not supported.
    """

    def __init__(self, store: SqliteStore) -> None:
        self._store = store

    def __enter__(self) -> SqliteStore:
        self._store._in_transaction = True
        self._store._conn.execute("BEGIN")
        return self._store

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:
        if exc_type is None:
            self._store._conn.execute("COMMIT")
        else:
            self._store._conn.execute("ROLLBACK")
        self._store._in_transaction = False
        return False  # propagate the exception



class BlobStore:
    """Content-addressed on-disk storage for large raw artifacts."""

    def __init__(self, root: str, threshold_bytes: int = 1024) -> None:
        self.root = root
        self.threshold = threshold_bytes
        os.makedirs(root, exist_ok=True)

    def put(self, content: str) -> tuple[str, str, int]:
        """Store ``content``; return (sha256, path, size). Always content-addressed."""
        data = content.encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()
        rel = os.path.join(digest[:2], digest[2:])
        abs_path = os.path.join(self.root, rel)
        if not os.path.exists(abs_path):
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            with open(abs_path, "wb") as fh:
                fh.write(data)
        return digest, abs_path, len(data)

    def should_externalize(self, content: str) -> bool:
        return len(content.encode("utf-8")) >= self.threshold

    def get(self, path: str) -> str:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()


class SqliteStore:
    """Single SQLite database implementing every repository Protocol."""

    def __init__(self, db_path: str, blob_store: BlobStore | None = None) -> None:
        self.db_path = db_path
        self.blob_store = blob_store
        self._in_transaction = False
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _commit(self) -> None:
        """Commit unless a transaction is active (the transaction owns the commit)."""
        if not self._in_transaction:
            self._conn.commit()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, metadata TEXT
            );
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY, project_id TEXT, kind TEXT, value TEXT
            );
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, project_id TEXT, target_id TEXT, status TEXT
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, scan_id TEXT, area TEXT, description TEXT
            );
            CREATE TABLE IF NOT EXISTS agent_runs (
                id TEXT PRIMARY KEY, task_id TEXT, agent TEXT
            );
            CREATE TABLE IF NOT EXISTS tool_runs (
                id TEXT PRIMARY KEY, tool_name TEXT, tool_version TEXT, capability TEXT,
                target TEXT, project_id TEXT, target_id TEXT, scan_id TEXT, task_id TEXT,
                agent_run_id TEXT, runtime TEXT, status TEXT, exit_code INTEGER,
                command TEXT, stdout TEXT, stderr TEXT, timeout_s INTEGER,
                started_at TEXT, finished_at TEXT, limits TEXT
            );
            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY, tool_run_id TEXT, kind TEXT, format TEXT,
                content TEXT, path TEXT, sha256 TEXT, size_bytes INTEGER, created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY, scan_id TEXT, tool_run_id TEXT, tool TEXT,
                type TEXT, target TEXT, raw TEXT, tool_version TEXT, source TEXT,
                raw_format TEXT, artifact_id TEXT, artifact_sha256 TEXT,
                normalized TEXT, created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, title TEXT, severity TEXT, confidence TEXT,
                status TEXT, affected_component TEXT, root_cause TEXT,
                attack_path TEXT, evidence TEXT, reproduction TEXT,
                remediation TEXT, refs TEXT, locations TEXT
            );
            """
        )
        self._commit()

    def close(self) -> None:
        self._conn.close()

    # ---- Unit-of-work / transactions ----
    def transaction(self):
        """Context manager for atomic multi-record operations.

        Usage:
            with store.transaction():
                store.add_tool_run(run)
                store.add_evidence(ev)

        On exception, all writes inside the block are rolled back, so partial
        failures do not leave misleading state.
        """
        return _Transaction(self)

    # ---- Projects ----
    def add_project(self, project_id: str, name: str, metadata: dict | None = None) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO projects (id, name, metadata) VALUES (?,?,?)",
            (project_id, name, json.dumps(metadata or {})),
        )
        self._commit()

    def get_project(self, project_id: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        return dict(row) if row else None

    def list_projects(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute("SELECT * FROM projects").fetchall()]

    # ---- Targets ----
    def add_target(self, target_id: str, project_id: str, kind: str, value: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO targets (id, project_id, kind, value) VALUES (?,?,?,?)",
            (target_id, project_id, kind, value),
        )
        self._commit()

    def get_target(self, target_id: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
        return dict(row) if row else None

    def list_targets(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute("SELECT * FROM targets").fetchall()]

    # ---- Scans ----
    def add_scan(self, scan_id: str, project_id: str, target_id: str, status: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO scans (id, project_id, target_id, status) VALUES (?,?,?,?)",
            (scan_id, project_id, target_id, status),
        )
        self._commit()

    def get_scan(self, scan_id: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def list_scans(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute("SELECT * FROM scans").fetchall()]

    # ---- Tasks ----
    def add_task(self, task_id: str, scan_id: str, area: str, description: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO tasks (id, scan_id, area, description) VALUES (?,?,?,?)",
            (task_id, scan_id, area, description),
        )
        self._commit()

    def get_task(self, task_id: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        return dict(row) if row else None

    def list_tasks(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute("SELECT * FROM tasks").fetchall()]

    # ---- Agent runs ----
    def add_agent_run(self, agent_run_id: str, task_id: str, agent: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO agent_runs (id, task_id, agent) VALUES (?,?,?)",
            (agent_run_id, task_id, agent),
        )
        self._commit()

    def get_agent_run(self, agent_run_id: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM agent_runs WHERE id=?", (agent_run_id,)).fetchone()
        return dict(row) if row else None

    def list_agent_runs(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute("SELECT * FROM agent_runs").fetchall()]

    # ---- Tool runs ----
    def add_tool_run(self, run: ToolRun) -> None:
        # externalize large stdout/stderr into the blob store
        stdout, stderr = run.stdout, run.stderr
        if self.blob_store and self.blob_store.should_externalize(stdout):
            _digest, path, _size = self.blob_store.put(stdout)
            stdout = f"blob:{path}"
        if self.blob_store and self.blob_store.should_externalize(stderr):
            _digest, path, _size = self.blob_store.put(stderr)
            stderr = f"blob:{path}"

        self._conn.execute(
            """INSERT OR REPLACE INTO tool_runs
               (id, tool_name, tool_version, capability, target, project_id, target_id,
                scan_id, task_id, agent_run_id, runtime, status, exit_code, command,
                stdout, stderr, timeout_s, started_at, finished_at, limits)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                run.id, run.tool_name, run.tool_version, run.capability, run.target,
                run.context.project_id, run.context.target_id,
                run.context.scan_id, run.context.task_id, run.context.agent_run_id,
                run.runtime, run.status.value, run.exit_code, json.dumps(run.command),
                stdout, stderr, run.timeout_s, run.started_at, run.finished_at,
                json.dumps(run.limits.to_dict()),
            ),
        )
        self._commit()

    def get_tool_run(self, tool_run_id: str) -> ToolRun | None:
        row = self._conn.execute("SELECT * FROM tool_runs WHERE id=?", (tool_run_id,)).fetchone()
        if row is None:
            return None
        return self._tool_run_from_row(row)

    def list_tool_runs(self) -> list[ToolRun]:
        return [self._tool_run_from_row(r) for r in self._conn.execute("SELECT * FROM tool_runs").fetchall()]

    def _tool_run_from_row(self, row: sqlite3.Row) -> ToolRun:
        from ..execution.models import ExecutionContext, ResourceLimits
        from ..models import RunStatus

        return ToolRun(
            id=row["id"], tool_name=row["tool_name"], tool_version=row["tool_version"],
            capability=row["capability"], target=row["target"],
            context=ExecutionContext(
                project_id=row["project_id"] or "",
                target_id=row["target_id"] or "",
                scan_id=row["scan_id"] or "",
                task_id=row["task_id"] or "",
                agent_run_id=row["agent_run_id"] or "",
            ),
            command=json.loads(row["command"] or "[]"), runtime=row["runtime"],
            status=RunStatus(row["status"]), exit_code=row["exit_code"],
            stdout=row["stdout"] or "", stderr=row["stderr"] or "",
            timeout_s=row["timeout_s"], started_at=row["started_at"] or "",
            finished_at=row["finished_at"] or "",
            limits=ResourceLimits.from_dict(json.loads(row["limits"] or "{}")),
        )

    # ---- Artifacts ----
    def add_artifact(self, artifact: Artifact) -> None:
        content = artifact.content
        path = artifact.path
        sha256 = artifact.sha256
        if self.blob_store and self.blob_store.should_externalize(content) and not path:
            sha256, path, _size = self.blob_store.put(content)
            content = ""
        self._conn.execute(
            """INSERT OR REPLACE INTO artifacts
               (id, tool_run_id, kind, format, content, path, sha256, size_bytes, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (artifact.id, artifact.tool_run_id, artifact.kind, artifact.format,
             content, path, sha256, artifact.size_bytes, artifact.created_at),
        )
        self._commit()

    def get_artifact(self, artifact_id: str) -> Artifact | None:
        row = self._conn.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
        if row is None:
            return None
        return Artifact(
            id=row["id"], tool_run_id=row["tool_run_id"], kind=row["kind"], format=row["format"],
            content=row["content"] or "", path=row["path"] or "", sha256=row["sha256"] or "",
            size_bytes=row["size_bytes"], created_at=row["created_at"],
        )

    def list_artifacts(self) -> list[Artifact]:
        out = []
        for r in self._conn.execute("SELECT * FROM artifacts").fetchall():
            out.append(Artifact(
                id=r["id"], tool_run_id=r["tool_run_id"], kind=r["kind"], format=r["format"],
                content=r["content"] or "", path=r["path"] or "", sha256=r["sha256"] or "",
                size_bytes=r["size_bytes"], created_at=r["created_at"],
            ))
        return out

    # ---- Evidence ----
    def add_evidence(self, evidence: Evidence) -> None:
        raw = evidence.raw
        artifact_id = evidence.artifact_id
        artifact_sha256 = evidence.artifact_sha256
        if self.blob_store and self.blob_store.should_externalize(raw) and not artifact_id:
            artifact_sha256, path, _size = self.blob_store.put(raw)
            artifact_id = f"blob:{path}"
            raw = ""
        self._conn.execute(
            """INSERT OR REPLACE INTO evidence
               (id, scan_id, tool_run_id, tool, type, target, raw, tool_version, source,
                raw_format, artifact_id, artifact_sha256, normalized, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (evidence.id, evidence.scan_id, evidence.tool_run_id, evidence.tool,
             evidence.type.value, evidence.target, raw, evidence.tool_version,
             evidence.source, evidence.raw_format, artifact_id, artifact_sha256,
             json.dumps(evidence.normalized) if evidence.normalized else None,
             evidence.created_at),
        )
        self._commit()

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        row = self._conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if row is None:
            return None
        raw = row["raw"] or ""
        if row["artifact_id"] and row["artifact_id"].startswith("blob:") and self.blob_store:
            raw = self.blob_store.get(row["artifact_id"][5:])
        return Evidence(
            id=row["id"], scan_id=row["scan_id"] or "", tool_run_id=row["tool_run_id"] or "",
            tool=row["tool"], type=EvidenceType(row["type"]), target=row["target"],
            raw=raw, tool_version=row["tool_version"] or "", source=row["source"] or "",
            raw_format=row["raw_format"] or "", artifact_id=row["artifact_id"] or "",
            artifact_sha256=row["artifact_sha256"] or "",
            normalized=json.loads(row["normalized"]) if row["normalized"] else None,
            created_at=row["created_at"] or "",
        )

    def list_evidence(self) -> list[Evidence]:
        out: list[Evidence] = []
        for r in self._conn.execute("SELECT id FROM evidence").fetchall():
            ev = self.get_evidence(r["id"])
            if ev is not None:
                out.append(ev)
        return out

    # ---- Findings ----
    def add_finding(self, finding: Finding) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO findings
               (id, title, severity, confidence, status, affected_component, root_cause,
                attack_path, evidence, reproduction, remediation, refs, locations)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (finding.id, finding.title, finding.severity.value, finding.confidence.value,
             finding.status.value, finding.affected_component, finding.root_cause,
             finding.attack_path, json.dumps(finding.evidence), finding.reproduction,
             finding.remediation, json.dumps(finding.references),
             json.dumps([loc.to_dict() for loc in finding.locations])),
        )
        self._commit()

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self._conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if row is None:
            return None
        return Finding(
            id=row["id"], title=row["title"], severity=Severity(row["severity"]),
            confidence=Confidence(row["confidence"]), status=FindingStatus(row["status"]),
            affected_component=row["affected_component"] or "", root_cause=row["root_cause"] or "",
            attack_path=row["attack_path"] or "", evidence=json.loads(row["evidence"] or "[]"),
            reproduction=row["reproduction"] or "", remediation=row["remediation"] or "",
            references=json.loads(row["refs"] or "[]"),
            locations=[
                EvidenceLocation(kind=EvidenceLocationKind(loc["kind"]), value=loc["value"])
                for loc in json.loads(row["locations"] or "[]")
            ],
        )

    def list_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for r in self._conn.execute("SELECT id FROM findings").fetchall():
            f = self.get_finding(r["id"])
            if f is not None:
                out.append(f)
        return out
