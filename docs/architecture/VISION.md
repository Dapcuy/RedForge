# RedForge — Vision

## What this is (and is not)

RedForge is **not** "a pile of security tools run in Docker."

RedForge is a **modular AI security research platform** that composes five layers:

| Layer | Role | Carrier |
|-------|------|---------|
| Knowledge | *What* to look for and *how* to reason about a target | `SKILL.md` |
| Reasoning | *Deciding* what to do, in what order, and why | AI agents |
| Capability | *Doing* the concrete work (scan, fuzz, analyze) | security tools |
| Execution | *Running* tools in a clean, consistent, isolated environment | Docker runtime |
| Validation | *Proving* a finding is real before it is reported | evidence + correlation |

## The target shape

```
                    ┌─────────────────────┐
                    │      AI AGENT        │
                    │ Hermes / lainnya     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    ORCHESTRATOR     │
                    │  Skill Resolver     │
                    │  Tool Resolver      │
                    │  Planner            │
                    │  Policy             │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
          Web/AppSec        CodeSec           Web3
              │                │                │
              ▼                ▼                ▼
          Strix/Caido      Code Analysis     Smart Contract
              │                │                │
              └────────────────┼────────────────┘
                               ▼
                         VALIDATION
                               │
                               ▼
                           EVIDENCE
                               │
                               ▼
                        CORRELATION
                               │
                               ▼
                           FINDINGS
                               │
                               ▼
                            REPORT
```

## Guiding principles

1. **Prove, don't assert.** A tool saying "reentrancy" is a *candidate*. A finding is only reported after it is correlated and validated. `Detected != Validated`.
2. **Skills are knowledge, not commands.** A skill declares *what capability* it needs — it never hard-codes "run Docker then Nuclei." The Tool Registry maps capability → concrete tool.
3. **The platform is agent-agnostic.** Hermes is one possible brain; the core must not depend on any single agent or LLM vendor.
4. **Tools are swappable.** Every tool sits behind a Runtime Interface. Docker is the MVP runtime; Podman/containerd may be added later without touching skills.
5. **One vertical slice before breadth.** We prove `Target → Profile → Skill → Agent → Tool → Runtime → Evidence → Finding → Report` end-to-end for a single domain before expanding.

## Inspiration (methodology, not code)

| Source | What we take |
|--------|--------------|
| Anthropic Cybersecurity Skills | `SKILL.md` as a knowledge/instruction layer |
| Strix | dynamic security agent patterns |
| open·kritt | code-security research orchestration (break → parallel agents → dedup → validate → report) |
| Pashov (ai-web3-security, skills) | Web3 audit methodology: X-Ray, multi-pass, fuzzing, invariant testing, PoC |
| Caido | HTTP/web traffic analysis as a *capability* |
| Docker | execution environment / isolation |

**We are not building a "Frankenstein repo" that copies these projects.** We extract ideas and methodologies and build our own core architecture with clean interfaces.
