# Skill Specification — v0.2

> Status: **Implemented (schema v2)**. Defines the `SKILL.md` format and the
> Skill Registry/Resolver contracts. v0.2 adds `schema_version`, `validation`,
> `evidence_requirements`, and `composes`.

## 1. Purpose

A Skill is a **knowledge unit**. It teaches an agent *what to look for* on a target and *how to reason* about it. It is **not** a script and **not** a command list.

Key property: a Skill declares **capabilities it requires** (abstract verbs), never concrete tools.

## 2. Directory taxonomy

```
skills/
├── web/          # web application security
│   ├── wordpress/  laravel/  django/  express/  react/  nextjs/  vue/  generic/
├── api/          # api surface security
│   ├── rest/  graphql/  authentication/  authorization/  business-logic/  oauth/
├── code/         # source-code security
│   ├── frontend/ (react, nextjs, vue, javascript)
│   ├── backend/  (nodejs, express, django, fastapi, laravel, spring)
│   └── architecture/ (api, authentication, authorization, business-logic)
├── cloud/
├── network/
└── web3/
    ├── reconnaissance/  evm/  solidity/  defi/  fuzzing/  poc/  solana/  move/  zk/
    └── solidity/ (access-control, reentrancy, oracle, signature, upgradeability,
                   proxy, storage, accounting, low-level)
```

## 3. SKILL.md frontmatter (required fields)

```yaml
---
name: wordpress-security
domain: web
version: 0.1.0
schema_version: "2.0"             # semver of the SKILL.md schema itself
requires:                          # capabilities (abstract), NEVER tool names
  - technology-detection
  - vulnerability-scanning
  - http-analysis
validation:                        # how a candidate is validated (schema v2)
  - every CVE match confirmed against the detected version
evidence_requirements:             # what evidence a finding must carry (schema v2)
  - http response demonstrating the vulnerable endpoint/version
composes: []                       # other skills this composes (cross-framework)
triggers:                          # how the Skill Resolver matches it
  technology: [wordpress]
  indicators: [wp-content, wp-login.php, xmlrpc.php]
  framework: [wordpress]
severity_focus: [high, critical]
---
```

### Field reference

| Field | Required | Meaning |
|-------|----------|---------|
| `name` | ✅ | unique skill id |
| `domain` | ✅ | `web` / `api` / `code` / `cloud` / `network` / `web3` |
| `version` | ✅ | semver of the skill content |
| `schema_version` | ✅ (defaults `2.0`) | semver of the SKILL.md schema |
| `requires` | ✅ | list of **capabilities** |
| `validation` | recommended (schema v2) | how a candidate finding is validated |
| `evidence_requirements` | recommended (schema v2) | evidence a finding must carry |
| `composes` | optional | other skill names this skill composes |
| `triggers` | recommended | technology / indicators / framework matchers |
| `severity_focus` | optional | which severities the skill cares about |

## 4. Body sections (all optional, recommended)

```markdown
## Objective
## Prerequisites
## Methodology
## Tools/Capabilities
## Analysis steps
## Validation
## Evidence requirements
## Expected output
```

## 5. Resolver behavior

```
TargetProfile ──▶ Skill Resolver ──▶ Relevant Skills
```

- Match `triggers.technology` and `triggers.framework` against the profile.
- Match `triggers.indicators` against raw fingerprints (headers, paths, files).
- Sort by specificity (more specific framework skills before generic ones).
- Union of `requires` for all resolved skills → the **capability set** the run needs.

## 6. Registry

- `SkillRegistry`: loads all `SKILL.md` files into an index (name → parsed skill).
- `SkillResolver`: given a `TargetProfile`, returns ordered relevant skills.
- No skill may name a tool. Violation = validation error at load time.
