---
name: solana-security
domain: web3
version: 0.1.0
schema_version: "2.0"
requires:
  - static-analysis
  - fuzzing
  - source-scanning
validation:
  - confirmed via unit test or local validator PoC
evidence_requirements:
  - code location + reasoning
  - test/poc showing the flaw
triggers:
  framework: [solana, anchor]
  technology: [rust]
  indicators: ["anchor.toml", "programs/", "Cargo.toml"]
severity_focus: [high, critical]
---

## Objective
Audit Solana programs (Rust/Anchor): account validation, signer checks,
CPI safety, and PDA derivation.

## Prerequisites
- Solana program source (Anchor project).

## Methodology
1. Map instructions and their account contexts.
2. Verify signer + owner checks on every account.
3. Audit CPIs for missing `invoke_signed` / signer authority.
4. Review PDA seeds for collision/canonicalization.

## Validation
Confirmed via unit test or local validator PoC.

## Evidence requirements
- Code location + reasoning; test/PoC showing the flaw.
