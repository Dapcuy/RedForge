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

**All 10 milestones implemented** (Phase 0 → Phase 10). The core platform is
functional with 59 passing tests. Remaining work is hardening, real Docker
image builds, and live multi-agent wiring.

```
01. Architecture        ✅  Phase 0
02. Docker Runtime      ✅  Phase 1 (runtime interface + Dockerfiles; daemon needed to run)
03. Tool Registry       ✅  Phase 1 (9 tool manifests)
04. Skill Engine        ✅  Phase 2 (parser + registry + resolver)
05. Evidence/Finding    ✅  Phase 3 (dedup + correlation + judge)
06. Code Analysis       ✅  Phase 4 (profiler + planner)
07. Web Dynamic Test    ✅  Phase 5 (policy + Caido/Strix adapters)
08. Web3/EVM Security   ✅  Phase 6 (Solidity pipeline)
09. Multi-Agent         ✅  Phase 8 (interface + dispatcher)
10. Web Dashboard       ✅  Phase 9 (stdlib dashboard skeleton)
```

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

---

*Private repository. Phase 0 in progress.*
