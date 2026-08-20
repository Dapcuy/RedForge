# RedForge

> **Modular AI Security Research Platform.**
> Knowledge (SKILL.md) + Reasoning (AI agents) + Capability (security tools) + Execution (Docker) + Validation (evidence/correlation).

RedForge is *not* a pile of security tools in Docker. It composes five layers into one pipeline:

```
Target (Git repo | URL)
   ──▶ Profile ──▶ Skill Resolver ──▶ Agent ──▶ Tool ──▶ Docker Runtime
   ──▶ Evidence ──▶ Correlation ──▶ Finding ──▶ Report
```

## Status

The **architecture is implemented** across all 10 milestones (Phase 0 → Phase 10),
but this is **not yet "fully functional"** — see the distinction below.

**Implemented (code + tests):** the execution pipeline, tool registry, skill
engine, evidence/finding engine, profiler, policy engine, multi-agent interface,
and SQLite persistence all exist and are unit/integration/E2E tested.

**Not yet fully functional (requires real infra + live wiring):** the Docker
runtime images have not been built or smoke-tested (daemon needed), agents are
not yet wired to a live LLM, and the dashboard is a skeleton.

```text
01. Architecture        ✅  Phase 0
02. Docker Runtime      🟡  Phase 1 (interface + Dockerfiles written; images not built/tested)
03. Tool Registry       ✅  Phase 1 (9 tool manifests)
04. Skill Engine        ✅  Phase 2 (parser + registry + resolver)
05. Evidence/Finding    ✅  Phase 3 (dedup + correlation + judge)
06. Code Analysis       ✅  Phase 4 (profiler + planner)
07. Web Dynamic Test    🟡  Phase 5 (policy engine + adapters written; tools not wired live)
08. Web3/EVM Security   ✅  Phase 6 (Solidity pipeline)
09. Multi-Agent         🟡  Phase 8 (interface + dispatcher; no live LLM agent yet)
10. Web Dashboard       🟡  Phase 9 (stdlib skeleton; not a full UI)
```

✅ = implemented and tested · 🟡 = implemented, needs real infra/live wiring.

### Hardening status (P0/P1/P2)

- **P0 — Execution architecture:** `ExecutionContext` + stable correlation IDs,
  `ToolRequest`/`ToolRun`/`Artifact` models, and a single execution path
  `Agent → ToolRequest → Policy → Resolver → Executor → Runtime`. Agents never
  touch the runtime directly. ✅
- **P0 — Evidence/provenance:** evidence references `scan_id`, `tool_run_id`,
  tool version, timestamps, source, and artifact/hash. ✅
- **P0 — Runtime safety:** DockerRuntime applies CPU/memory/PID/filesystem/
  network/timeout limits; the Policy engine enforces them. ✅
- **P1 — Persistence:** repository Protocols + SQLite backend + on-disk blob
  store for large artifacts (DB holds references only). ✅
- **P1 — Agent:** structured `AgentObservation`/`AgentDecision`/
  `AgentToolRequest`/`AgentFindingCandidate`. ✅
- **P2 — Hygiene:** CI (test/lint/type/docker), `docs/THIRD_PARTY.md`. ✅

## Quick start

```bash
# install (python 3.11+)
uv pip install -e ".[dev]"

# run the test suite
python -m pytest -q

# inspect the CLI
python -m core --help
python -m core tools list
python -m core skills resolve --framework nextjs --technology react
python -m core profile --path .
python -m core web3 --path path/to/solidity

# dashboard
python -m web.dashboard  # -> http://127.0.0.1:8000

# runtime (requires Docker Desktop running)
docker compose build
docker compose up -d
python -m core run --capability vulnerability-scanning --target https://in-scope.example
```

## Layering (enforced)

```
Skill ──requires──▶ Capability ──resolved by──▶ Tool ──runs on──▶ Runtime
```

| Document | What it defines |
|----------|-----------------|
| [Vision](docs/architecture/VISION.md) | what the platform is, and the five-layer model |
| [Architecture](docs/architecture/ARCHITECTURE.md) | repo layout, pipeline, component responsibilities |
| [Skill Spec](docs/architecture/SKILL_SPEC.md) | the `SKILL.md` knowledge format + resolver |
| [Tool Spec](docs/architecture/TOOL_SPEC.md) | capability → tool registry |
| [Runtime Spec](docs/architecture/RUNTIME_SPEC.md) | runtime interface + Docker backend |
| [Evidence Spec](docs/architecture/EVIDENCE_SPEC.md) | evidence capture + normalization |
| [Finding Spec](docs/architecture/FINDING_SPEC.md) | dedup → correlation → judge → finding |
| [Agent Spec](docs/architecture/AGENT_SPEC.md) | agent-agnostic interface (Hermes is a plug-in) |
| [Policy Spec](docs/architecture/POLICY_SPEC.md) | scope + restrictions before execution |
| [Licensing](docs/architecture/LICENSING.md) | licensing strategy (open decision) |
| [Third-Party](docs/THIRD_PARTY.md) | third-party inspiration + licensing/attribution |
| [Roadmap](docs/ROADMAP.md) | 10 milestones + phases |

## Domains

```
skills/
├── web/     # web application security (wordpress, laravel, django, express, react, nextjs, vue, generic)
├── api/     # rest, graphql, authentication, authorization, business-logic, oauth
├── code/    # frontend, backend, architecture
├── cloud/
├── network/
└── web3/    # evm, solidity, defi, fuzzing, poc, solana, move, zk
```

## Principles

1. **Prove, don't assert** — `Detected != Validated`.
2. **Skills are knowledge, not commands** — they declare capabilities, never tools.
3. **Agent-agnostic core** — Hermes is one possible brain.
4. **Swappable runtime** — Docker now, Podman later, no skill changes.
5. **One vertical slice first.**

## Inspiration (methodology, not code)

Anthropic Cybersecurity Skills · Strix · open·kritt · Pashov (ai-web3-security / skills) · Caido · Docker

See [`docs/THIRD_PARTY.md`](docs/THIRD_PARTY.md) for licensing and attribution.
