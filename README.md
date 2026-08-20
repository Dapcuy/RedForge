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

**Phase 0 — Architecture & Specification.** No large-scale coding yet; we are defining the contracts that the rest of the build depends on.

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
