---
name: web-security-baseline
domain: web
version: 0.1.0
schema_version: "2.0"
requires:
  - http-analysis
  - technology-detection
validation:
  - candidate must map to a reachable endpoint or config finding
evidence_requirements:
  - http response or config snapshot
triggers: {}
severity_focus: [medium, high]
---

## Objective
Cross-framework web security baseline: transport, headers, and fingerprinting
checks that apply to any web application regardless of framework.

## Prerequisites
- A running web target.

## Methodology
1. Check TLS config and security headers (HSTS, CSP, X-Frame-Options).
2. Fingerprint server and framework.
3. Look for exposed admin/debug endpoints.

## Validation
Confirm with a reachable response or configuration snapshot.

## Evidence requirements
- HTTP response or config snapshot.

## Expected output
Baseline candidate findings that framework-specific skills can build on.
