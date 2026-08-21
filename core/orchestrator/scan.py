"""Orchestrator: the end-to-end scan spine (hardened).

Binds the whole pipeline in one place, proving the vertical slice:

    target -> profile -> skill -> agent -> tool request -> policy
           -> tool -> runtime -> artifact -> evidence -> finding -> SQLite

Scan lifecycle: queued -> running -> completed/failed/partial/cancelled/timeout.
Exceptions from policy, runtime, agent, tool, or persistence update the scan
state correctly via try/except/finally.

Evidence → Finding correctness: evidence produced by a tool run is correlated
into the FindingEngine BEFORE findings are persisted. Agent finding candidates
are ingested as CANDIDATE (hypotheses), never auto-confirmed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..evidence.models import make_evidence
from ..execution.models import ExecutionContext
from ..execution.service import ToolExecutionService
from ..findings.engine import FindingEngine
from ..ids import project_id, scan_id, target_id, task_id
from ..persistence.protocols import (
    AgentRunRepository,
    ArtifactRepository,
    EvidenceRepository,
    FindingRepository,
    ProjectRepository,
    ScanRepository,
    TargetRepository,
    ToolRunRepository,
)
from ..profiling.profiler import profile_directory, profile_url
from .scan_status import ScanStatus


@dataclass
class ScanResult:
    """The outcome of an end-to-end scan."""
    context: ExecutionContext
    status: ScanStatus = ScanStatus.QUEUED
    error: str = ""
    relevant_skills: list[str] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)
    tool_runs: list[Any] = field(default_factory=list)
    evidence: list[Any] = field(default_factory=list)


class Orchestrator:
    """Coordinates a scan from target to persisted findings."""

    def __init__(
        self,
        projects: ProjectRepository,
        targets: TargetRepository,
        scans: ScanRepository,
        tool_runs: ToolRunRepository,
        artifacts: ArtifactRepository,
        evidence_repo: EvidenceRepository,
        findings_repo: FindingRepository,
        execution: ToolExecutionService | None = None,
        agent_runs: AgentRunRepository | None = None,
    ) -> None:
        self.projects = projects
        self.targets = targets
        self.scans = scans
        self.tool_runs = tool_runs
        self.artifacts = artifacts
        self.evidence_repo = evidence_repo
        self.findings_repo = findings_repo
        self.execution = execution
        self.agent_runs = agent_runs
        self._last_evidence: Any | None = None

    def _authorize_target(self, target_value: str) -> str | None:
        """Register a source-dir target as an AuthorizedWorkspace (trusted side).

        Returns the opaque workspace_id (empty for URL targets). The agent can
        only reference this id — it never sees or invents the host path.
        """
        if self.execution is None:
            return None
        if target_value.startswith(("http://", "https://")):
            return None
        from pathlib import Path

        root = str(Path(target_value).expanduser().resolve())
        ws = self.execution.workspaces.register(root, label="scan-target")
        return ws.id

    def _persist_scan(self, ctx: ExecutionContext, status: ScanStatus) -> None:
        self.scans.add_scan(ctx.scan_id, ctx.project_id, ctx.target_id, status.value)

    def _persist_tool_records(self, run, artifacts, scan_id_value: str, source: str) -> None:
        """Persist a ToolRun + artifacts + evidence atomically when possible.

        Uses the backend's unit-of-work (``transaction``) when the repository
        exposes it; otherwise falls back to per-record commits. Partial
        failures roll back, so no misleading scan state is left behind.
        """
        ev = make_evidence(
            scan_id=scan_id_value, tool_run_id=run.id, tool=run.tool_name,
            target=run.target, raw=run.stdout, raw_format="text",
            tool_version=run.tool_version, source=source,
        )
        self._last_evidence = ev

        tx = getattr(self.tool_runs, "transaction", None)
        if tx is not None:
            with tx():
                self.tool_runs.add_tool_run(run)
                for art in artifacts:
                    self.artifacts.add_artifact(art)
                self.evidence_repo.add_evidence(ev)
        else:
            self.tool_runs.add_tool_run(run)
            for art in artifacts:
                self.artifacts.add_artifact(art)
            self.evidence_repo.add_evidence(ev)

    def run(
        self,
        target_value: str,
        project_name: str = "default",
        skills_dir: str = "skills",
        tools_dir: str = "tools",
        agent: Any = None,
    ) -> ScanResult:
        """Run a full scan against a URL or source directory.

        If ``agent`` is provided, its tool requests are executed through the
        Tool Execution Service and converted to evidence + findings.
        """
        # 1. Correlation IDs + queue the scan.
        pid = project_id(project_name)
        tid = target_id(target_value)
        sid = scan_id(project_name, target_value)
        ctx = ExecutionContext(project_id=pid, target_id=tid, scan_id=sid)

        result = ScanResult(context=ctx, status=ScanStatus.QUEUED)

        try:
            # 2. Persist project/target/scan -> running.
            self.projects.add_project(pid, project_name)
            is_url = target_value.startswith(("http://", "https://"))
            kind = "url" if is_url else "source-dir"
            self.targets.add_target(tid, pid, kind, target_value)
            self._persist_scan(ctx, ScanStatus.RUNNING)

            # 3. Profile the target.
            profile = profile_url(target_value) if is_url else profile_directory(target_value)

            # 3b. Policy target scope gate (fail-closed, before any agent/tool work).
            if self.execution is not None:
                from ..models import Target, TargetKind

                tkind = TargetKind.URL if is_url else TargetKind.SOURCE_DIR
                self.execution.policy.check_target(Target(kind=tkind, value=target_value))

            # 3c. Authorize the source target as a Workspace (trusted side).
            #     The agent will only ever see the opaque workspace_id.
            authorized_ws_id = self._authorize_target(target_value)

            # 4. Resolve skills (if a skills dir is available).
            relevant_skills: list[str] = []
            try:
                from ..skills.registry import SkillRegistry
                from ..skills.resolver import SkillResolver

                registry = SkillRegistry()
                if registry.load_dir(skills_dir) > 0:
                    resolver = SkillResolver(registry)
                    relevant_skills = resolver.expanded_skill_names(profile)
            except FileNotFoundError:
                relevant_skills = []
            result.relevant_skills = relevant_skills

            # 5. Run the agent (if provided) and execute its tool requests.
            partial = False
            if agent is not None:
                from ..agents.dispatcher import Dispatcher
                from ..orchestrator.planner import Task, break_repository_into_tasks

                engine = FindingEngine()
                dispatcher = Dispatcher(engine, context=ctx)
                dispatcher.register(
                    agent.name, agent,
                    areas=["backend", "frontend", "web3", "config", "web", "api"],
                )

                if is_url:
                    tasks = [Task(
                        id=task_id(sid, "url"), area="web", description=f"Scan {target_value}",
                        target=target_value,
                    )]
                else:
                    plan = break_repository_into_tasks(target_value, profile)
                    tasks = plan.tasks
                    for t in tasks:
                        t.target = target_value

                dispatch = dispatcher.dispatch(tasks)
                result.findings.extend(dispatch.findings)

                if self.execution is not None:
                    for req in dispatch.tool_requests:
                        try:
                            # The agent never picks the host path; it gets the
                            # authorized workspace_id from the orchestrator.
                            if authorized_ws_id:
                                req.workspace_id = authorized_ws_id
                                # Source tools (semgrep/slither/foundry) scan
                                # the workspace root by default; inject the
                                # relative path unless the agent set one.
                                req.arguments.setdefault("path", ".")
                            outcome = self.execution.execute(req)
                            run = outcome.tool_run
                            self._persist_tool_records(run, outcome.artifacts, sid, req.source)
                            result.tool_runs.append(run)
                            result.evidence.append(self._last_evidence)
                        except Exception as exc:
                            partial = True
                            result.error = f"tool execution failed: {exc}"

                # Evidence must be correlated into the engine BEFORE findings persist.
                engine.correlate(result.evidence)

            # 6. Persist findings (only after correlation).
            for f in result.findings:
                self.findings_repo.add_finding(f)

            # 7. Terminal state.
            result.status = ScanStatus.PARTIAL if partial else ScanStatus.COMPLETED
            self._persist_scan(ctx, result.status)
            return result

        except Exception as exc:
            # Any policy/runtime/agent/persistence failure -> FAILED.
            result.status = ScanStatus.FAILED
            result.error = str(exc)
            try:
                self._persist_scan(ctx, result.status)
            except Exception as persist_exc:
                result.error += f"; scan state persist failed: {persist_exc}"
            return result
