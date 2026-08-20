# Evidence Specification — v0.1

> Status: **Draft (Phase 0)**.

## 1. Purpose

Evidence is a **core component**, not a reporting afterthought. Every tool run produces evidence; evidence is the only input the Finding engine trusts.

```
Tool ──▶ Evidence ──▶ Correlation ──▶ Finding
```

## 2. Evidence sources

| Tool | Evidence type |
|------|---------------|
| nuclei | http evidence |
| semgrep | code evidence |
| slither | smart-contract evidence |
| echidna | fuzz evidence |
| foundry | PoC evidence |
| caido | http interaction evidence |
| strix | dynamic testing evidence |

## 3. Evidence record (normalized)

```yaml
evidence:
  id: ev_01H...
  run_id: run_01H...
  tool: nuclei
  type: http
  target: https://target
  timestamp: 2026-08-20T17:00:00Z
  raw:
    format: jsonl
    digest: sha256:...
  normalized:
    # tool-specific, but schema-validated
```

### Requirements

- `raw` always stores the **original output + a hash** (immutable, reproducible).
- `normalized` is the structured, queryable form.
- Evidence is **never deleted**; it may only be superseded (new evidence id, links back).

## 4. Normalization

- Each evidence `type` has a normalizer (`web.http`, `code.semgrep`, `web3.slither`, ...).
- Unknown output = stored as `type: generic` with `normalized: null` + a warning (never dropped).

## 5. Correlation

- Correlation groups evidence by (target, component, location).
- Multiple evidence pointing at the same root cause feeds the same candidate finding.
- Correlation output is the input to the Finding judge.
