---
name: wordpress-security
domain: web
version: 0.1.0
requires:
  - vulnerability-scanning
  - content-discovery
  - http-analysis
triggers:
  technology: [wordpress]
  indicators: [wp-content, wp-login.php, xmlrpc.php]
severity_focus: [high, critical]
---

## Objective
Enumerate and assess a WordPress target: core version, plugins/themes, and known
vulnerabilities.

## Prerequisites
- Running WordPress URL.

## Methodology
1. Fingerprint core version + plugins/themes.
2. Enumerate wp-content paths (ffuf).
3. Template-scan known CVEs (nuclei).
4. Check xmlrpc.php abuse surface.

## Tools/Capabilities
- vulnerability-scanning
- content-discovery
- http-analysis

## Validation
Every CVE match must be confirmed against the detected version.

## Evidence requirements
- HTTP response demonstrating the vulnerable endpoint/version.

## Expected output
Versioned findings with CVE references.
