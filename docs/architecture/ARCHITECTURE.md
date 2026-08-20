# RedForge Architecture — v0.2

> Status: **Implemented (hardened)**. This documents the current architecture,
> which reflects the P0/P1 hardening work on top of the Phase 0 design.

## Repository layout

```
RedForge/
├── agents/                 # agent adapters (hermes, generic, future)
├── core/                   # platform engine
│   ├── ids.py              # stable, typed correlation IDs
│   ├── models.py           # Target, Tool, RunResult, RunContext, TargetProfile
│   ├── execution/          # ExecutionContext, ToolRequest, ToolRun, Artifact, ResourceLimits
│   │   └── service.py      # ToolExecutionService (the single execution gate)
│   ├── orchestrator/       # planner + scan spine (end-to-end)
│   ├── skills/             # SKILL.md parser, registry, resolver (schema v2)
│   ├── tools/              # tool registry + capability mapping
│   ├── runtime/            # runtime interface + hardened docker runtime
│   ├── policy/             # scope + restriction + resource-limit engine
│   ├── evidence/           # provenance-aware evidence + normalization
│   ├── findings/           # dedup, correlation, judge, finding model
│   ├── profiling/          # target profiling (repo/URL → tech profile)
│   ├── persistence/        # repository Protocols + SQLite + blob store
│   └── agents/             # Agent interface (structured output) + dispatcher
├── skills/                 # the knowledge layer (content)
│   ├── web/  api/  code/  cloud/  network/  web3/
├── runtimes/               # docker image definitions per domain
│   ├── base/  web/  code/  web3/  privileged/
├── integrations/           # external capability adapters
│   ├── caido/  strix/
├── web/dashboard/          # (Phase 9) web UI skeleton
├── docs/                   # specs + architecture + roadmap
└── tests/                  # unit + integration + E2E tests
```

## Core pipeline (the vertical slice)

```
Target (Git repo | URL)
        │
        ▼
   [profiling]        → TargetProfile (languages, frameworks, stack)
        │
        ▼
   [skills]           → Skill Resolver → relevant skills (schema v2, composes)
        │
        ▼
   [orchestrator]     → scan spine → tasks → dispatch to agents
        │
        ▼
   [agents]           → structured AgentResult (observations / tool_requests / findings)
        │
        ▼
   [execution]        → ToolRequest → Policy → Tool Resolver → Tool Executor → Runtime
        │
        ▼
   [runtime]          → Docker Runtime (resource-limited) → ToolRun + Artifact
        │
        ▼
   [evidence]         → provenance-aware Evidence (scan_id, tool_run_id, version, hash)
        │
        ▼
   [findings]         → dedup → correlation → judge → Finding
        │
        ▼
   [persistence]      → SQLite (references) + blob store (large artifacts)
```

## Execution architecture (the enforced single path)

Agents never invoke Docker, subprocess, shell, or the runtime directly. Every
tool execution flows through one gate:

```
Agent → ToolRequest → Policy → Tool Resolver → Tool Executor → Runtime
```

- `ToolRequest` is an intent (capability + optional preferred tool), not a command.
- `Policy` produces effective `ResourceLimits` (most-restrictive-wins) and
  rejects out-of-scope / destructive / privileged requests fail-closed.
- `Tool Execution Service` (`core/execution/service.py`) owns the whole chain
  and emits provenance-aware `ToolRun` + `Artifact` records.

## Correlation IDs

Stable, typed, prefixed IDs tie every record back to its origin:

```
project_id · target_id · scan_id · task_id · agent_run_id ·
tool_run_id · artifact_id · evidence_id · finding_id
```

## Persistence

The core depends only on repository **Protocols** (`core/persistence/protocols.py`),
never on SQLite. `SqliteStore` is the first backend; large raw artifacts are
stored on disk (content-addressed `BlobStore`) and referenced by path/hash in
the DB.

## Layering rule (enforced)

- `skills/` (knowledge) references **capabilities**, never tools.
- `core/tools` (registry) maps **capability → tool**.
- `core/runtime` maps **tool → execution environment** (runtime interface; Podman later).
- `core/execution` is the only path from request to runtime.
- `core/` imports nothing from `agents/` or `integrations/` (agent-agnostic).

```
Skill ──requires──▶ Capability ──resolved by──▶ Tool ──runs on──▶ Runtime
```

## Non-goals (deliberately deferred)

- Kubernetes, Podman (runtime interface is ready; no second backend yet)
- 100+ tools (9 manifests exist)
- Solana, Move, ZK (skills exist; pipelines are EVM/Solidity-only)
- Full dashboard (skeleton only)
