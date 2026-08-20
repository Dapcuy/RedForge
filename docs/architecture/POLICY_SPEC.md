# Policy & Scope Specification — v0.1

> Status: **Draft (Phase 0)**.

## 1. Purpose

The Policy engine is a **pre-execution gate**. Before any tool runs, the platform checks scope and restrictions. This matters because RedForge can drive powerful capabilities.

```
Target ──▶ Scope Check ──▶ Policy ──▶ Allowed? ──▶ Execute
```

## 2. Scope & restriction model

```yaml
policy:
  scope:
    allowed_targets:
      - "*.example.local"
      - "github.com/Dapcuy/*"
  restrictions:
    destructive_actions: false
    external_targets: false
    privileged_runtime: false
    max_parallel_runs: 4
```

## 3. Enforcement points

| Gate | When | Behavior on deny |
|------|------|------------------|
| Target scope | before planning | run refused with clear reason |
| Destructive actions | before tool selection | destructive tools excluded |
| External targets | before network tools | outbound denied |
| Privileged runtime | before runtime selection | `privileged/` images blocked |
| Concurrency cap | before dispatch | queued |

## 4. Rules

- Policy is **declarative** (`policy.yaml`) and loaded per-run.
- Denials are **fail-closed** and always logged with the reason.
- No agent can override policy; only an explicit user-acknowledged config change can.
