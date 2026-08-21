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

**Docker execution (2nd hardening pass):** a tiny deterministic test runtime
image is built and exercised by `tests/test_docker_e2e.py` — it verifies real
container execution, workspace mounting (read-only `/workspace`), artifact
creation, evidence creation, and SQLite persistence against a live Docker
daemon.

**Real Docker source-scan vertical slice (3rd pass):** the `code-runtime`
image (Semgrep **1.95.0** pinned) is built, and `tests/test_semgrep_e2e.py`
runs the **actual Semgrep binary** against a vulnerable fixture mounted at
`/workspace:ro`. It proves the full production-like flow:

```
host/tests/fixtures/vuln_app/app.py
        │  (mounted read-only)
        ▼
container:/workspace/app.py
        │
        ▼
semgrep /workspace --json --config=/workspace/semgrep-rules.yml
        │
        ▼
Artifact → Evidence → Correlation → Finding (confirmed) → SQLite
```

The Semgrep result is real (not faked), and the finding is persisted with
provenance (scan_id, tool_run_id, artifact_id, evidence_id, file path, line).

**Not yet fully functional (requires live wiring):** agents are not yet wired
to a live LLM, and the dashboard is a skeleton.

```text
01. Architecture        ✅  Phase 0
02. Docker Runtime      ✅  Phase 1 (base + code-runtime built; real Semgrep 1.95.0 source scan validated in Docker)
03. Tool Registry       ✅  Phase 1 (10 tool manifests, pinned versions, trust, input schema)
04. Skill Engine        ✅  Phase 2 (parser + registry + resolver, schema v2)
05. Evidence/Finding    ✅  Phase 3 (dedup + correlation + judge + REJECTED + lifecycle)
06. Code Analysis       ✅  Phase 4 (profiler + planner)
07. Web Dynamic Test    🟡  Phase 5 (policy engine + adapters written; web-runtime image not validated)
08. Web3/EVM Security   🟡  Phase 6 (Solidity pipeline; web3-runtime image not validated)
09. Multi-Agent         🟡  Phase 8 (interface + dispatcher; no live LLM/Hermes agent yet)
10. Web Dashboard       🟡  Phase 9 (stdlib skeleton; not a full UI)
```

✅ = implemented and tested · 🟡 = implemented, needs real infra/live wiring.

### Docker validation status (current truth)

| Runtime | Built? | Validated with real tool? |
|---------|--------|---------------------------|
| `redforge/base:latest` | ✅ | — (base only) |
| `redforge/code-runtime:latest` | ✅ | ✅ **Semgrep 1.95.0** real source scan (`test_semgrep_e2e.py`) |
| `redforge/web-runtime:latest` | ✅ | ✅ **nuclei 3.3.7 / httpx 1.6.9 / ffuf 2.1.0** real scans vs local lab (`test_web_runtime_e2e.py`) |
| `redforge/test-runtime:latest` | ✅ | ✅ e2e-probe (workspace mount + persistence) |
| `redforge/web3-runtime:latest` | ❌ not built | ❌ slither/foundry/echidna/mythril not validated |
| `redforge/privileged:latest` | ❌ not built | ❌ nmap not validated (policy-gated) |

**Not wired yet:** live LLM/Hermes agent (adapter exists, no live connection).
**Dashboard:** stdlib skeleton, not a full UI.

### Hardening status (P0/P1/P2)

- **P0 — Execution architecture:** `ExecutionContext` + stable correlation IDs,
  `ToolRequest`/`ToolRun`/`Artifact` models, and a single execution path
  `Agent → ToolRequest → Policy → Resolver → Executor → Runtime`. Agents never
  touch the runtime directly. ✅
- **P0 — Workspace:** first-class Workspace abstraction; Docker mounts the
  authorized source tree read-only at `/workspace` + writable temp; no
  arbitrary host mounts. ✅
- **P0 — Workspace authorization (final pass):** `AuthorizedWorkspaceRegistry` —
  agents reference an opaque `workspace_id`, never a host path. Unknown ids and
  unregistered paths are rejected; restricted/system paths (`.ssh`, `/etc`, ...)
  are blocked; symlink escape rejected. ✅
- **P0 — Policy:** network modeled as ordered capability (none < bridge < host),
  escalation denied; scope/network/capability/destructive/privileged separated;
  external URLs denied by default (fail-closed). ✅
- **P0 — Concurrency:** `max_parallel_runs` enforced atomically via semaphore. ✅
- **P0 — Evidence/provenance:** evidence references `scan_id`, `tool_run_id`,
  tool version, timestamps, source, artifact/hash. Evidence → Finding lifecycle
  with candidate/REJECTED and structured locations. ✅
- **P0 — Scan lifecycle:** queued/running/completed/failed/partial/cancelled/
  timeout with try/except/finally state updates. ✅
- **P1 — Runtime:** Docker E2E test (tiny deterministic runtime) verifies real
  container execution + workspace mount + artifact/evidence + SQLite. ✅
- **P1 — Reproducibility:** tool versions pinned; trust metadata per manifest. ✅
- **P0 — Temp dir security (final pass):** per-run writable dir is
  RedForge-managed (`<tmp>/redforge-runs/<run-id>`), OUTSIDE the user-controlled
  source tree; source tree stays read-only; symlink/reparse-point mount
  redirects rejected. ✅
- **P1 — Persistence:** repository Protocols + SQLite + blob store; full
  ExecutionContext restore; unit-of-work transactions. ✅
- **P1 — Registry:** deterministic priority selection + input-schema validation
  + image trust. ✅
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
