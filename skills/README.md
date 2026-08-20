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

*No skills are authored yet — that is Phase 2 (Skill Engine).*
