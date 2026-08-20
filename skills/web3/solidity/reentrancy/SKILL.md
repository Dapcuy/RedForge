---
name: solidity-reentrancy
domain: web3
version: 0.1.0
schema_version: "2.0"
requires:
  - static-analysis
  - solidity-analysis
  - fuzzing
validation:
  - reentrancy confirmed only by a working PoC (mainnet-fork or local anvil)
evidence_requirements:
  - slither detector output
  - fuzz/invariant trace
  - poc transaction showing the exploit
triggers:
  framework: [solidity, foundry]
  technology: [evm]
severity_focus: [high, critical]
---

## Objective
Detect and validate reentrancy vulnerabilities in Solidity contracts.

## Prerequisites
- Solidity source (Foundry project preferred).

## Methodology
1. Identify external calls followed by state mutation.
2. Trace read-only vs state-changing paths.
3. Confirm with Slither detectors.
4. Build an Echidna/Foundry invariant + PoC.

## Validation
A reentrancy is only confirmed by a working PoC (mainnet-fork or local anvil).

## Evidence requirements
- Slither detector output.
- Fuzz/invariant trace.
- PoC transaction showing the exploit.

## Expected output
Confirmed reentrancy finding with root cause and remediation.
