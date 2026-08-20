# RedForge Roadmap

> The disciplined path: prove one vertical slice before expanding. **Do not build everything at once.**

## Milestones (simplified 10-step order)

```
01. Architecture      ──▶
02. Docker Runtime    ──▶
03. Tool Registry     ──▶
04. Skill Engine      ──▶
05. Evidence/Finding  ──▶
06. Code Analysis     ──▶
07. Web Dynamic Test  ──▶
08. Web3/EVM Security ──▶
09. Multi-Agent       ──▶
10. Web Dashboard
```

## Phases

| Phase | Name | Goal | Key deliverable |
|-------|------|------|-----------------|
| 0 | Architecture & Specification | no large-scale coding | Architecture v0.1, Skill/Tool/Runtime/Evidence/Finding specs |
| 1 | Minimal Runtime | CLI → executor → Docker → JSON | `docker compose up -d`, Tool Executor, initial tools (httpx, nuclei, ffuf, nmap, semgrep) |
| 2 | Skill Engine | SKILL.md parser + registry + resolver | skill resolution from target profile |
| 3 | Evidence + Finding | tool output → evidence → finding | dedup, correlation, severity, confidence |
| 4 | Code Security | open·kritt-style orchestration | repo → profiler → skills → research → static → evidence |
| 5 | Web Dynamic Security | integrate Caido/Strix/browser | source → running target → dynamic analysis → evidence |
| 6 | Web3 MVP | EVM/Solidity only | Foundry, Slither, Echidna, Mythril pipeline |
| 7 | Web3 Expansion | after EVM stable | Solana, Move/Sui, ZK/Circom |
| 8 | Multi-Agent | after single-agent pipeline stable | recon/code/web/web3/exploit/judge agents |
| 9 | Dashboard | web UI | projects, targets, scans, findings, evidence, skill library |
| 10 | Public Release | core stable | docs, examples, security policy, contribution guide, license, images |

## The one thing to prove first (vertical slice)

```
Git/URL Target ──▶ Profiler ──▶ Skill Resolver ──▶ Agent ──▶ Tool ──▶ Docker ──▶ Evidence ──▶ Finding ──▶ Report
```

## Deferred (hold the line)

- Kubernetes, Podman, 100+ tools
- Solana, ZK, cloud (until EVM is stable)
- Multi-agent (Phase 8), Dashboard (Phase 9)
