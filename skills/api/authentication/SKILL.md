---
name: api-authentication
domain: api
version: 0.1.0
requires:
  - http-analysis
  - vulnerability-scanning
triggers:
  technology: [rest, api]
  indicators: ["/api/", "authorization: bearer"]
severity_focus: [high]
---

## Objective
Assess authentication and session management on a REST API.

## Prerequisites
- Running API target with known endpoints.

## Methodology
1. Map auth endpoints and token issuance.
2. Test auth bypass, weak JWT, and missing/incorrect authz.
3. Check rate limiting on login.

## Validation
Authz flaws confirmed via direct request replay.

## Evidence requirements
- HTTP requests showing unauthorized access.

## Expected output
Authn/authz candidate findings.
