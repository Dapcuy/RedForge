---
name: move-security
domain: web3
version: 0.1.0
schema_version: "2.0"
requires:
  - static-analysis
  - source-scanning
validation:
  - confirmed via Move unit test
evidence_requirements:
  - code location + reasoning
  - test showing the flaw
triggers:
  framework: [move, sui]
  indicators: ["Move.toml", "sources/"]
severity_focus: [high]
---

## Objective
Audit Move/Sui modules: abilities, object ownership, and reentrancy
(which Move mostly prevents by construction).

## Prerequisites
- Move module source.

## Methodology
1. Review module abilities (`key`, `store`, `drop`, `copy`).
2. Check object ownership and transfer semantics.
3. Verify access control on privileged entry functions.
4. Look for flash-loan / dynamic-object pitfalls.

## Validation
Confirmed via Move unit test.

## Evidence requirements
- Code location + reasoning; test showing the flaw.
