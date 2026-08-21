# Skills — Knowledge Layer

This directory holds the **knowledge units** (`SKILL.md`) that teach agents *what to look for* on a target and *how to reason* about it.

## Taxonomy

```
skills/
├── web/      # wordpress, laravel, django, express, react, nextjs, vue, generic
├── api/      # rest, graphql, authentication, authorization, business-logic, oauth
├── code/     # frontend (react/nextjs/vue/javascript), backend (nodejs/express/django/fastapi/laravel/spring), architecture
├── cloud/
├── network/
└── web3/     # reconnaissance, evm, solidity, defi, fuzzing, poc, solana, move, zk
```

## Rules

- A skill declares **capabilities** it requires (see `docs/architecture/SKILL_SPEC.md`).
- A skill **never** names a tool. Tool mapping lives in `core/tools` (registry).
- Skill format and fields are defined in [`SKILL_SPEC.md`](../docs/architecture/SKILL_SPEC.md).

*Skills are authored per-domain; see the table below for current coverage.*

## Authored skills (8)

| Path | Skill |
|---|---|
| `api/authentication` | API authentication testing |
| `web/generic` | Web security baseline |
| `web/nextjs` | Next.js security |
| `web/wordpress` | WordPress security |
| `web3/move` | Move (Sui) security |
| `web3/solana` | Solana security |
| `web3/solidity/reentrancy` | Solidity reentrancy |
| `web3/zk` | ZK security |
