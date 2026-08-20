---
name: zk-circuit-security
domain: web3
version: 0.1.0
schema_version: "2.0"
requires:
  - static-analysis
  - constraint-analysis
validation:
  - confirmed via constraint trace or test vector
evidence_requirements:
  - circuit location + reasoning
  - failing constraint trace
triggers:
  framework: [circom, halo2, noir]
  indicators: ["circuits/", ".circom"]
severity_focus: [high, critical]
---

## Objective
Audit ZK circuits for under-constrained systems, soundness bugs, and
input malleability.

## Prerequisites
- Circuit source (Circom/Halo2/Noir).

## Methodology
1. Enumerate signals and constraints.
2. Check every output signal is constrained.
3. Look for unconstrained inputs (soundness breaks).
4. Review witness generation vs constraint consistency.

## Validation
Confirmed via constraint trace or test vector.

## Evidence requirements
- Circuit location + reasoning; failing constraint trace.
