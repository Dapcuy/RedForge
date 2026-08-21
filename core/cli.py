"""RedForge CLI — target -> tool -> runtime -> JSON (security-enforced).

Usage:
    redforge run --capability vulnerability-scanning --target https://example.com
    redforge run --tool semgrep --target ./repo --kind source-dir
    redforge tools list
    redforge tools resolve --capability static-analysis
    redforge skills list | resolve
    redforge profile --path ./repo | --url https://site
    redforge plan --path ./repo

All tool execution flows through ToolExecutionService, which enforces
AuthorizedWorkspace + Policy (fail-closed) before any runtime call — the CLI
cannot bypass the security boundary.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from .execution.service import ToolExecutionService
from .execution.workspace import AuthorizedWorkspaceRegistry
from .models import Target, TargetKind
from .policy.engine import Policy, PolicyEngine
from .runtime.base import DockerRuntime, RunError
from .tools.registry import ToolRegistry

DEFAULT_TOOLS_DIR = "tools"
DEFAULT_POLICY_FILE = "policy.yaml"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="redforge", description="RedForge security platform CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run a tool/capability against a target (policy-enforced)")
    run.add_argument("--capability", help="capability to resolve to a tool")
    run.add_argument("--tool", help="concrete tool name to run")
    run.add_argument("--target", required=True, help="URL, repo, or source-dir value")
    run.add_argument("--kind", choices=[k.value for k in TargetKind], default="url")
    run.add_argument("--tools-dir", default=DEFAULT_TOOLS_DIR)
    run.add_argument("--policy-file", default=DEFAULT_POLICY_FILE)
    run.add_argument("--path", help="relative path inside the workspace (source tools)")
    run.add_argument("--arg", action="append", default=[], help="tool argument KEY=VALUE")
    run.add_argument("--timeout", type=int, default=None)

    tl = sub.add_parser("tools", help="tool registry commands")
    tlsub = tl.add_subparsers(dest="tools_cmd", required=True)
    tl_list = tlsub.add_parser("list", help="list registered tools")
    tl_list.add_argument("--tools-dir", default=DEFAULT_TOOLS_DIR)
    tl_resolve = tlsub.add_parser("resolve", help="resolve a capability")
    tl_resolve.add_argument("--capability", required=True)
    tl_resolve.add_argument("--tools-dir", default=DEFAULT_TOOLS_DIR)

    sk = sub.add_parser("skills", help="skill engine commands")
    sksub = sk.add_subparsers(dest="skills_cmd", required=True)
    sk_list = sksub.add_parser("list", help="list loaded skills")
    sk_list.add_argument("--skills-dir", default="skills")
    sk_resolve = sksub.add_parser("resolve", help="resolve skills for a target profile")
    sk_resolve.add_argument("--skills-dir", default="skills")
    sk_resolve.add_argument("--technology", action="append", default=[])
    sk_resolve.add_argument("--framework", action="append", default=[])
    sk_resolve.add_argument("--indicator", action="append", default=[])

    prof = sub.add_parser("profile", help="profile a source directory or URL")
    prof.add_argument("--path", help="local source directory to profile")
    prof.add_argument("--url", help="URL to profile")

    plan = sub.add_parser("plan", help="break a repo into analysis tasks")
    plan.add_argument("--path", required=True, help="local source directory")
    plan.add_argument("--skills-dir", default="skills")

    w3 = sub.add_parser("web3", help="run the Solidity security pipeline")
    w3.add_argument("--path", required=True, help="path to Solidity source (Foundry project)")
    w3.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    scan = sub.add_parser("scan", help="run the full orchestrated scan (scope->profile->skill->tool->evidence->finding)")
    scan.add_argument("--target", required=True, help="URL or source-dir target (must be authorized)")
    scan.add_argument("--kind", choices=[k.value for k in TargetKind], default=None)
    scan.add_argument("--tools-dir", default=DEFAULT_TOOLS_DIR)
    scan.add_argument("--policy-file", default=DEFAULT_POLICY_FILE)
    scan.add_argument("--db", default=None, help="SQLite path for persistence (default: in-memory)")
    scan.add_argument("--no-agent", action="store_true",
                      help="skip the reference agent loop (profile + skill resolution only)")

    return parser


def _load_registry(tools_dir: str) -> ToolRegistry:
    registry = ToolRegistry()
    try:
        n = registry.load_dir(tools_dir)
    except FileNotFoundError:
        n = 0
    if n == 0:
        print(f"warning: no tool manifests found under {tools_dir!r}", file=sys.stderr)
    return registry


def _load_policy(policy_file: str) -> Policy:
    """Load a policy.yaml if present; otherwise the fail-closed default."""
    if policy_file and os.path.isfile(policy_file):
        try:
            import yaml
            with open(policy_file, "r", encoding="utf-8") as fh:
                return Policy.from_dict(yaml.safe_load(fh).get("policy", {}))
        except Exception as exc:
            print(f"warning: could not load policy {policy_file!r}: {exc}", file=sys.stderr)
    return Policy()


def _build_service(registry: ToolRegistry, policy: Policy) -> tuple[ToolExecutionService, AuthorizedWorkspaceRegistry]:
    """Build the secured execution service + shared workspace registry."""
    workspaces = AuthorizedWorkspaceRegistry()
    svc = ToolExecutionService(
        registry, DockerRuntime(), PolicyEngine(policy), workspaces=workspaces,
    )
    return svc, workspaces


def _parse_args_kv(items: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in items:
        if "=" not in item:
            out[item] = True
            continue
        k, v = item.split("=", 1)
        out[k] = v
    return out


def _cmd_run(args: argparse.Namespace) -> int:
    from .execution.models import ExecutionContext, ToolRequest
    from .ids import scan_id, target_id, tool_request_id

    registry = _load_registry(args.tools_dir)
    policy = _load_policy(args.policy_file)
    svc, workspaces = _build_service(registry, policy)

    # The CLI is a trusted caller: for source-dir targets it registers the
    # authorized workspace, so the tool can only ever see that root.
    target = Target(kind=TargetKind(args.kind), value=args.target)
    request = ToolRequest(
        id=tool_request_id("cli"),
        capability=args.capability or "",
        tool_name=args.tool or "",
        target=target,
        context=ExecutionContext("", target_id(args.target), scan_id("cli")),
        arguments=_parse_args_kv(args.arg),
    )
    if args.path:
        request.arguments["path"] = args.path

    if target.kind == TargetKind.SOURCE_DIR:
        try:
            ws = workspaces.register(target.value, label="cli-target")
            request.workspace_id = ws.id
        except Exception as exc:
            print(f"error: target is not an authorized workspace: {exc}", file=sys.stderr)
            return 1

    try:
        outcome = svc.execute(request)
    except (RunError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    run = outcome.tool_run
    print(json.dumps(run.to_dict(), indent=2))
    if run.status.value in ("success",):
        return 0
    return 1


def _cmd_tools(args: argparse.Namespace) -> int:
    registry = _load_registry(args.tools_dir)
    if args.tools_cmd == "list":
        for name, tool in sorted(registry.tools.items()):
            print(f"{name:12} [{tool.domain}] caps={','.join(tool.capabilities)} image={tool.image}")
        return 0
    if args.tools_cmd == "resolve":
        try:
            tool = registry.resolve_capability(args.capability)
        except KeyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({
            "capability": args.capability,
            "tool": tool.name,
            "domain": tool.domain,
            "image": tool.image,
            "entrypoint": tool.entrypoint,
        }, indent=2))
        return 0
    return 2


def _cmd_skills(args: argparse.Namespace) -> int:
    from .models import Target, TargetKind, TargetProfile
    from .skills.registry import SkillRegistry
    from .skills.resolver import SkillResolver

    registry = SkillRegistry()
    try:
        n = registry.load_dir(args.skills_dir)
    except FileNotFoundError:
        n = 0
    if n == 0:
        print(f"warning: no SKILL.md found under {args.skills_dir!r}", file=sys.stderr)

    if args.skills_cmd == "list":
        for name in registry.names():
            s = registry.get(name)
            if s is not None:
                print(f"{name:24} [{s.domain}] requires={','.join(s.requires)}")
        return 0

    if args.skills_cmd == "resolve":
        profile = TargetProfile(
            target=Target(TargetKind.URL, "<profile>"),
            technologies=args.technology,
            frameworks=args.framework,
            indicators=args.indicator,
        )
        resolver = SkillResolver(registry)
        matches = resolver.resolve(profile)
        if not matches:
            print("no matching skills")
            return 0
        for m in matches:
            print(f"{m.skill:24} specificity={m.specificity} matched_on={m.matched_on}")
        print("\nrequired capabilities:", resolver.required_capabilities(profile))
        return 0
    return 2


def _cmd_profile(args: argparse.Namespace) -> int:
    import json

    from .profiling.profiler import profile_directory, profile_url

    if args.path:
        profile = profile_directory(args.path)
    elif args.url:
        profile = profile_url(args.url)
    else:
        print("error: provide --path or --url", file=sys.stderr)
        return 2
    print(json.dumps(profile.to_dict(), indent=2))
    return 0


def _cmd_plan(args: argparse.Namespace) -> int:
    import json

    from .orchestrator.planner import break_repository_into_tasks
    from .profiling.profiler import profile_directory
    from .skills.registry import SkillRegistry
    from .skills.resolver import SkillResolver

    profile = profile_directory(args.path)
    plan = break_repository_into_tasks(args.path, profile)

    registry = SkillRegistry()
    try:
        registry.load_dir(args.skills_dir)
    except FileNotFoundError:
        pass
    resolver = SkillResolver(registry)
    relevant = resolver.skill_names(profile)

    out = plan.to_dict()
    out["relevant_skills"] = relevant
    out["required_capabilities"] = plan.capability_union
    print(json.dumps(out, indent=2))
    return 0


def _cmd_web3(args: argparse.Namespace) -> int:
    import json
    import uuid

    from .web3.pipeline import Web3Pipeline

    pipe = Web3Pipeline(args.path, run_id=str(uuid.uuid4())[:8])
    findings = pipe.run()

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        if not findings:
            print("no findings")
            return 0
        for f in findings:
            print(f"[{f.severity.value.upper():5}] {f.title}  ({f.status.value})")
            if f.root_cause:
                print(f"         root cause: {f.root_cause}")
            if f.affected_component:
                print(f"         component: {f.affected_component}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    """Full orchestrated scan: scope -> profile -> skill -> tool -> evidence -> finding."""
    import tempfile

    from .orchestrator.scan import Orchestrator
    from .persistence.store import BlobStore, SqliteStore

    registry = _load_registry(args.tools_dir)
    policy = _load_policy(args.policy_file)
    svc, _workspaces = _build_service(registry, policy)

    is_url = (args.kind == "url") or (args.kind is None and args.target.startswith(("http://", "https://")))
    _ = TargetKind.URL if is_url else TargetKind.SOURCE_DIR

    # Persistence: user-provided SQLite path, else a scratch DB.
    db_path = args.db
    temp_db = None
    if not db_path:
        tmp_dir = tempfile.mkdtemp(prefix="redforge-scan-")
        temp_db = os.path.join(tmp_dir, "scan.db")
        db_path = temp_db
    blob = BlobStore(os.path.join(os.path.dirname(os.path.abspath(db_path)), "blobs"))
    db = SqliteStore(db_path, blob_store=blob)

    orch = Orchestrator(
        projects=db, targets=db, scans=db, tool_runs=db, artifacts=db,
        evidence_repo=db, findings_repo=db, execution=svc,
    )

    agent = None
    if not getattr(args, "no_agent", False):
        from agents.generic import agents as _agents
        agent = _agents.ReconAgent() if is_url else _agents.CodeAgent()

    result = orch.run(
        target_value=args.target,
        project_name="cli-scan",
        tools_dir=args.tools_dir,
        agent=agent,
    )

    out = {
        "status": result.status.value,
        "error": result.error,
        "target": args.target,
        "scan_id": result.context.scan_id,
        "relevant_skills": result.relevant_skills,
        "findings": [f.to_dict() for f in result.findings],
        "tool_runs": [r.to_dict() for r in result.tool_runs],
        "evidence_count": len(result.evidence),
        "db": db_path,
    }
    print(json.dumps(out, indent=2))
    if result.status.value in ("completed", "partial"):
        return 0
    return 1


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "run":
        return _cmd_run(args)
    if args.command == "tools":
        return _cmd_tools(args)
    if args.command == "skills":
        return _cmd_skills(args)
    if args.command == "profile":
        return _cmd_profile(args)
    if args.command == "plan":
        return _cmd_plan(args)
    if args.command == "web3":
        return _cmd_web3(args)
    if args.command == "scan":
        return _cmd_scan(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
