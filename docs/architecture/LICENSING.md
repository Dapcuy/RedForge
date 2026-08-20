# Licensing Strategy — v0.1

> Status: **Draft (Phase 0)**. Open question for the owner.

## 1. Context

RedForge is currently a **private** repository (`Dapcuy/RedForge`). Phase 10 plans a public release. Licensing choice affects how freely the platform, skills, and runtime images can be reused.

## 2. Options considered

| License | Effect |
|---------|--------|
| **AGPL-3.0** | strongest copyleft; any network service built on it must open-source. Protects the platform from being closed. |
| **GPL-3.0** | copyleft for distribution, but not network-use. |
| **MIT / Apache-2.0** | permissive; simplest adoption, least protection. |
| **BUSL-1.1** | source-available; limits commercial/production use until it converts to an OS license. |

## 3. Layered consideration

- **Core platform** (`core/`) — the engine; likely the copyleft candidate.
- **Skills** (`skills/`) — knowledge; many ecosystems share these openly (MIT/CC). Our *format* can stay open while specific skill *content* may be licensed separately.
- **Runtimes** (`runtimes/`) — Dockerfile definitions; permissive is fine unless a tool's own license restricts redistribution.
- **Third-party tools** (nuclei, slither, foundry, etc.) — each retains its own license; we ship orchestration, not the tools themselves.

## 4. Recommendation

For a security-research platform that should stay open but discourage proprietary forks quietly swallowing the engine: **AGPL-3.0 for `core/`**, with permissive terms for `skills/` and `runtimes/`. Final call belongs to the owner — this is recorded as a decision point, not a ruling.
