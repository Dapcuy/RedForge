# RedForge Architecture — v0.1

> Status: **Draft (Phase 0)**. This document defines *intent and boundaries*, not final code.

## Repository layout

```
RedForge/
├── agents/                 # agent adapters (hermes, generic, future)
├── core/                   # platform engine
│   ├── orchestrator/       # planner + coordination
│   ├── skills/             # SKILL.md parser, registry, resolver
│   ├── tools/              # tool registry + capability mapping
│   ├── runtime/            # runtime interface + docker runtime
│   ├── policy/             # scope + restriction engine
│   ├── evidence/           # evidence capture + normalization
│   ├── findings/           # dedup, correlation, judge, finding model
│   └── profiling/          # target profiling (repo/URL → tech profile)
├── skills/                 # the knowledge layer (content)
│   ├── web/  api/  code/  cloud/  network/  web3/
├── runtimes/               # docker image definitions per domain
│   ├── base/  web/  code/  web3/  privileged/
├── integrations/           # external capability adapters
│   ├── caido/  strix/
├── web/dashboard/          # (Phase 9) web UI
├── docs/                   # specs + architecture + roadmap
└── tests/                  # unit + integration tests
```

## Core pipeline (the vertical slice)

```
Target (Git repo | URL)
        │
        ▼
   [profiling]        → TargetProfile (languages, frameworks, stack)
        │
        ▼
   [skills]           → Skill Resolver → relevant skills
        │
        ▼
   [orchestrator]     → Planner → ordered steps (guarded by policy)
        │
        ▼
   [tools]            → Tool Resolver → concrete tool + runtime
        │
        ▼
   [runtime]          → Docker Runtime → container execution → JSON result
        │
        ▼
   [evidence]         → normalize raw output → Evidence record
        │
        ▼
   [findings]         → dedup → correlation → judge → Finding
        │
        ▼
   [report]           → machine-readable + human-readable report
```

## Component responsibilities

| Component | Responsibility | Phase |
|-----------|----------------|-------|
| `profiling` | Detect tech stack from a repo or a running URL | 0 (spec), 4 (code) |
| `skills` | Parse/register/resolve `SKILL.md` knowledge units | 0 (spec), 2 (engine) |
| `tools` | Register tools, map capability → tool, expose runtime config | 0 (spec), 1 (registry) |
| `runtime` | Abstract execution; `run/stop/logs/inspect`; Docker impl first | 0 (spec), 1 (impl) |
| `policy` | Scope check before execution; restrictions (destructive, external, privileged) | 0 (spec), 1 (impl) |
| `evidence` | Capture, normalize, and store tool output as evidence | 0 (spec), 3 (impl) |
| `findings` | Dedup, correlate, judge, and promote candidates to confirmed findings | 0 (spec), 3 (impl) |
| `orchestrator` | Plan and drive the pipeline; single-agent first | 0 (spec), 2+ |
| `agents` | Adapter so Hermes/Claude/custom/local-LLM can drive the platform | 0 (spec), 8 (multi) |

## Layering rule (enforced from Phase 0)

- `skills/` (knowledge) references **capabilities**, never tools.
- `core/tools` (registry) maps **capability → tool**.
- `core/runtime` maps **tool → execution environment**.
- No layer may skip the layer below it.

```
Skill ──requires──▶ Capability ──resolved by──▶ Tool ──runs on──▶ Runtime
```

## Non-goals for v0.1 (deliberately deferred)

- Kubernetes, Podman, 100+ tools
- Solana, Move, ZK, Cosmos (post EVM stabilization)
- Multi-agent orchestration (Phase 8)
- Web dashboard (Phase 9)
