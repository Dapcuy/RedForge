# Contributing to RedForge

Thanks for helping build RedForge. This guide keeps the platform's core
principles intact.

## The layering rule (non-negotiable)

```
Skill ──requires──▶ Capability ──resolved by──▶ Tool ──runs on──▶ Runtime
```

- A **skill** declares capabilities, never tools.
- A **tool manifest** maps capabilities to tools.
- The **runtime interface** maps tools to an execution backend (Docker now).

PRs that break this layering (e.g. a skill hard-coding `nuclei`) will be asked
to change.

## Core vs. agents vs. integrations

- `core/` imports nothing from `agents/` or `integrations/`. Those are plug-ins.
- Adding an agent = implementing `core/agents/interface.py`'s `Agent`.
- Adding an integration = subclassing `integrations/base.py`'s `IntegrationAdapter`.

## Before you PR

1. **Run the tests** — `python -m pytest` must pass.
2. **Add tests** for new behavior (the suite is fast and dependency-light).
3. **Update specs** in `docs/architecture/` if you change a contract.

## Style

- Python 3.11+, standard library first (avoid new deps when stdlib suffices).
- Follow the existing dataclass + Protocol/ABC patterns in `core/`.
- Type hints on public functions.

## Commit style

- Phase commits: `Phase N: <summary>`.
- Fixes/chores: `fix: ...`, `chore: ...`.
