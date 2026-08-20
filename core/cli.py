"""RedForge CLI — the Phase 1 vertical slice: target -> tool -> runtime -> JSON.

Usage:
    redforge run --capability vulnerability-scanning --target https://example.com
    redforge tools list
    redforge tools resolve --capability static-analysis
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid

from .models import RunContext, Target, TargetKind
from .runtime.base import DockerRuntime, RunError
from .tools.executor import ToolExecutor
from .tools.registry import ToolRegistry

DEFAULT_TOOLS_DIR = "tools"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="redforge", description="RedForge security platform CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run a tool/capability against a target")
    run.add_argument("--capability", help="capability to resolve to a tool")
    run.add_argument("--tool", help="concrete tool name to run")
    run.add_argument("--target", required=True, help="URL, repo, or source-dir value")
    run.add_argument("--kind", choices=[k.value for k in TargetKind], default="url")
    run.add_argument("--tools-dir", default=DEFAULT_TOOLS_DIR)
    run.add_argument("--timeout", type=int, default=300)

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
    prof.add_argument("--url", help="URL to profile (stub in Phase 4)")

    plan = sub.add_parser("plan", help="break a repo into analysis tasks")
    plan.add_argument("--path", required=True, help="local source directory")
    plan.add_argument("--skills-dir", default="skills")

    w3 = sub.add_parser("web3", help="run the Solidity security pipeline")
    w3.add_argument("--path", required=True, help="path to Solidity source (Foundry project)")
    w3.add_argument("--json", action="store_true", help="emit machine-readable JSON")

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


def _cmd_run(args: argparse.Namespace) -> int:
    registry = _load_registry(args.tools_dir)
    executor = ToolExecutor(registry, DockerRuntime())
    target = Target(kind=TargetKind(args.kind), value=args.target)
    ctx = RunContext(run_id=str(uuid.uuid4())[:8], timeout_s=args.timeout)

    try:
        if args.tool:
            result = executor.run_tool(args.tool, target, ctx)
        elif args.capability:
            result = executor.run_capability(args.capability, target, ctx)
        else:
            print("error: provide --capability or --tool", file=sys.stderr)
            return 2
    except (RunError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.exit_code == 0 else 1


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
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
