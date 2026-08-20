# Runtimes — Execution Layer (Docker)

Per-domain runtime images. **Not one giant 500-tool image** — isolation and maintainability win.

```
runtimes/
├── base/         # shared OS + python/node/go + common libs
├── web/          # httpx, nuclei, ffuf, browser
├── code/         # semgrep, language runtimes, dependency analyzers
├── web3/         # foundry, slither, echidna, mythril
└── privileged/   # host/network access tools (gated by policy)
```

See [`RUNTIME_SPEC.md`](../docs/architecture/RUNTIME_SPEC.md) for the runtime interface and Docker backend contract.

*No images are defined yet — that is Phase 1 (Minimal Runtime).*
