---
name: nextjs-security
domain: web
version: 0.1.0
requires:
  - technology-detection
  - source-scanning
  - http-analysis
triggers:
  framework: [nextjs, next.js]
  technology: [react, nodejs]
  indicators: [".next/", "next.config.js"]
severity_focus: [high, critical]
---

## Objective
Identify security weaknesses specific to Next.js applications (SSR/SSG, API routes,
middleware, image optimization, and RSC boundaries).

## Prerequisites
- Target Profile with `nextjs` framework detected.
- Access to source (repo/dir) and/or a running URL.

## Methodology
1. Map route surface: pages/, app/, API routes.
2. Audit middleware and auth boundaries.
3. Check SSR data leaks (props serialization, `getServerSideProps`).
4. Review server actions and RSC trust boundaries.

## Tools/Capabilities
- technology-detection
- source-scanning
- http-analysis

## Validation
Each candidate must have a reproducible request or a concrete code path.

## Evidence requirements
- HTTP request/response pair, or
- Source location (file:line) plus reasoning.

## Expected output
Candidate findings with affected component, root cause, and attack path.
