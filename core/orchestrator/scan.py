"""Orchestrator: the end-to-end scan spine.

Binds the whole pipeline in one place, proving the vertical slice:

    target -> profile -> skill -> agent -> tool request -> policy
           -> tool -> runtime -> artifact -> evidence -> finding -> SQLite

The orchestrator coordinates the layers but owns no layer's logic. It depends
on the repository Protocols (persistence), the Policy engine, the Tool
Execution Service, and the Dispatcher — never on concrete backends directly.
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


@dataclass
class ScanResult:
    """The outcome of an end-to-end scan."""
    context: ExecutionContext
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
        # 1. Correlation IDs.
        pid = project_id(project_name)
        tid = target_id(target_value)
        sid = scan_id(project_name, target_value)
        ctx = ExecutionContext(project_id=pid, target_id=tid, scan_id=sid)

        # 2. Persist project/target/scan.
        self.projects.add_project(pid, project_name)
        is_url = target_value.startswith(("http://", "https://"))
        kind = "url" if is_url else "source-dir"
        self.targets.add_target(tid, pid, kind, target_value)
        self.scans.add_scan(sid, pid, tid, "running")

        # 3. Profile the target.
        if is_url:
            profile = profile_url(target_value)
        else:
            profile = profile_directory(target_value)

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

        # 5. Run the agent (if provided) and execute its tool requests.
        result = ScanResult(context=ctx, relevant_skills=relevant_skills)
        if agent is not None:
            from ..agents.dispatcher import Dispatcher
            from ..orchestrator.planner import Task, break_repository_into_tasks

            dispatcher = Dispatcher(FindingEngine(), context=ctx)
            dispatcher.register(agent.name, agent, areas=["backend", "frontend", "web3", "config", "web", "api"])

            if is_url:
                tasks: list[Task] = [Task(
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
                    outcome = self.execution.execute(req)
                    run = outcome.tool_run
                    self.tool_runs.add_tool_run(run)
                    for art in outcome.artifacts:
                        self.artifacts.add_artifact(art)
                    ev = make_evidence(
                        scan_id=sid, tool_run_id=run.id, tool=run.tool_name,
                        target=run.target, raw=run.stdout, raw_format="text",
                        tool_version=run.tool_version, source=req.source,
                    )
                    self.evidence_repo.add_evidence(ev)
                    result.tool_runs.append(run)
                    result.evidence.append(ev)

        # 6. Persist findings.
        for f in result.findings:
            self.findings_repo.add_finding(f)

        self.scans.add_scan(sid, pid, tid, "completed")
        return result
