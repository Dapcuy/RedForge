# Tool Registry Specification — v0.1

> Status: **Draft (Phase 0)**.

## 1. Purpose

The Tool Registry is the single place that maps a **capability** (abstract) to a **tool** (concrete), and attaches a **runtime** requirement. Skills never know about tools; only the registry does.

```
Skill ──requires──▶ capability ──▶ [Tool Registry] ──▶ tool + runtime
```

## 2. Tool manifest

```yaml
name: nuclei
domain: web
capabilities:
  - vulnerability-scanning
  - template-scanning
runtime:
  image: redforge/web-runtime
  entrypoint: nuclei
  version: 3.3.x
inputs:
  target: url
output:
  format: jsonl
```

```yaml
name: slither
domain: web3
capabilities:
  - static-analysis
  - solidity-analysis
runtime:
  image: redforge/web3-runtime
  version: 0.10.x
inputs:
  target: source-dir
output:
  format: json
```

### Field reference

| Field | Required | Meaning |
|-------|----------|---------|
| `name` | ✅ | unique tool id |
| `domain` | ✅ | `web` / `code` / `web3` / ... |
| `capabilities` | ✅ | capabilities this tool satisfies |
| `runtime` | ✅ | image + entrypoint + version |
| `inputs` | ✅ | what the tool consumes |
| `output` | ✅ | expected output format |

## 3. Capability → tool resolution

- **1 capability → many tools** is allowed (e.g. `vulnerability-scanning` → `nuclei`, `nuclei-community`, ...).
- Selection order: policy allow-list → runtime availability → default/preferred tool.
- A capability with **no** registered tool = a run-time planning error, reported clearly.

## 4. Initial tool set (Phase 1 — MVP)

| Tool | Domain | Capabilities |
|------|--------|--------------|
| httpx | web | http-analysis, technology-detection |
| nuclei | web | vulnerability-scanning |
| ffuf | web | fuzzing, content-discovery |
| nmap | network | port-scanning, service-detection |
| semgrep | code | static-analysis, source-scanning |

## 5. Rules

- The registry is declarative data, not code.
- Adding a tool = adding a manifest (plus its runtime image), nothing else.
- Tool manifests are validated at load: duplicate names, missing `runtime`, and unknown `domain` are errors.
