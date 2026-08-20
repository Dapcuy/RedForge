# Security Policy

## Reporting a Vulnerability

RedForge is a security research platform. Security of the platform itself
matters as much as what it helps you find.

**Do not open a public issue for a vulnerability.** Instead, report it
privately to the maintainers. Include:

- Affected component / version
- Steps to reproduce
- Impact (what an attacker could do)
- Any suggested fix

We will acknowledge within 72 hours and aim to resolve critical issues
promptly.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (main) | ✅ |

## Scope

The security policy covers the **platform itself** (`core/`, `agents/`,
`integrations/`, `web/`). It does not cover:

- Third-party tools bundled by reference (nuclei, slither, foundry, etc. —
  each keeps its own security policy).
- Misuse of the platform against targets you do not own or lack permission
  to test.

## Responsible Use

RedForge drives powerful security capabilities. **Only use it against
systems you own or have explicit written authorization to test.** The
platform ships fail-closed by default (see `docs/architecture/POLICY_SPEC.md`):
destructive actions, external targets, and privileged runtimes are disabled
until you explicitly enable them.
