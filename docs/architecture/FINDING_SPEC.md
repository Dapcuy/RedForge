# Finding Specification — v0.1

> Status: **Draft (Phase 0)**.

## 1. Purpose

The Finding engine turns raw signals into **trustworthy, deduplicated findings**. It solves the classic failure: *10 agents → 10 findings → actually 2 vulnerabilities.*

## 2. Pipeline

```
Agent A ──┐
Agent B ──┤
Agent C ──┤
Tool A ───┤
Tool B ───┤
PoC ──────┘
      │
      ▼
  Deduplication ──▶ Correlation ──▶ Judge ──▶ Final Finding
```

## 3. Finding model

```yaml
finding:
  id: fnd_01H...
  title: "Unprotected admin endpoint"
  severity: high | medium | low | informational
  confidence: low | medium | high
  status: candidate | analyzed | validated | confirmed
  affected_component: ...
  root_cause: ...
  attack_path: ...
  evidence: [ev_..., ev_...]
  reproduction: ...
  remediation: ...
  references: [...]
```

### Field reference

| Field | Meaning |
|-------|---------|
| `title` | short human summary |
| `severity` | impact rating |
| `confidence` | how sure we are it is real |
| `status` | lifecycle (see below) |
| `affected_component` | what is vulnerable |
| `root_cause` | *why* it is vulnerable |
| `attack_path` | how an attacker reaches it |
| `evidence` | linked evidence ids |
| `reproduction` | steps / PoC |
| `remediation` | fix guidance |
| `references` | CWE, advisory, docs |

## 4. Lifecycle (validation is the core principle)

```
Candidate ──▶ Analyzed ──▶ Validated ──▶ Confirmed
```

- `Detected != Validated`. A slither "potential reentrancy" is a **candidate**.
- Promotion path: AI reasoning → generate test → fuzz → PoC → confirm.
- Only `confirmed` findings are reported as vulnerabilities.

## 5. Deduplication & Judge

- Dedup: group findings by (component, root-cause signature).
- Judge: weighs evidence, confidence, and severity to emit a final ranked finding list.
