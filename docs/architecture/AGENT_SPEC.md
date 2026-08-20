# Agent Interface Specification — v0.1

> Status: **Draft (Phase 0)**.

## 1. Purpose

RedForge is **agent-agnostic**. Hermes is one possible brain — **not the core platform**. Any agent (Claude, custom, local LLM) can drive the platform as long as it speaks the interface.

## 2. Adapter layout

```
agents/
├── hermes/
├── generic/
└── future/
```

## 3. Agent interface (contract)

An agent consumes a **plan** and returns **actions**:

```python
class Agent(Protocol):
    def plan(self, target: TargetProfile, skills: list[Skill]) -> Plan: ...
    def next_action(self, ctx: RunContext) -> AgentAction: ...
    def reason(self, evidence: list[Evidence]) -> CandidateFinding: ...
```

## 4. Hermes adapter (reference implementation)

- `agents/hermes/` maps Hermes' tool-calling surface onto the interface.
- Hermes can act as: planner, per-domain analyst, or judge — but the platform works without it.

## 5. Rules

- Core (`core/`) imports **nothing** from `agents/`. Adapters are plug-ins.
- Agent output is validated and constrained by `policy/` before any tool executes.
- Agent choice is a runtime configuration, never a code dependency.
