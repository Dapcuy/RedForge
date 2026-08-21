# Runtimes — Execution Layer (Docker)

Per-domain runtime images. **Not one giant 500-tool image** — isolation and
maintainability win.

## Images

```
runtimes/
├── base/         # python 3.11-slim + node + go + curl/git (shared base) — BUILT
├── web/          # nuclei 3.3.7, httpx 1.6.9, ffuf 2.1.0 (pinned) — BUILT + E2E-validated
├── code/         # semgrep==1.95.0 (pinned) — BUILT + validated by real Docker E2E
├── web3/         # foundry, slither, echidna, mythril (built on base)
├── privileged/   # nmap (needs host/network access; gated by policy)
└── test/         # tiny deterministic e2e tool (Docker E2E test only, not production)
```

## Build

```bash
docker build -t redforge/base:latest runtimes/base
docker build -t redforge/code-runtime:latest runtimes/code
docker build -t redforge/web-runtime:latest runtimes/web
docker compose build            # build all production images
docker compose build test       # build the tiny E2E test runtime
```

`redforge/code-runtime` is a **real production tool image** that has been
validated: it installs Semgrep **1.95.0** (pinned in the Dockerfile, must match
`tools/semgrep.tool.yaml`), and `tests/test_semgrep_e2e.py` runs the real binary
against a vulnerable fixture mounted at `/workspace:ro`.

`redforge/web-runtime` is also **built + validated**: nuclei **3.3.7**,
projectdiscovery/httpx **1.6.9**, ffuf **2.1.0** (pinned via `go install @version`).
`tests/test_web_runtime_e2e.py` runs the real binaries against a LOCAL lab
server (127.0.0.1) — no external targets.

## Workspace mounting

For source-dir targets, the runtime mounts the **authorized Workspace**:

- the source tree at `/workspace` (read-only)
- a controlled writable temp dir at `/workspace-tmp` (for tools that need
  build/temp output — foundry, semgrep cache)

No other host mounts are ever added. The workspace is derived from the target
by the execution service and validated; agents/requests cannot add mounts.

## Tool versions

Tool manifests (`tools/*.tool.yaml`) pin exact versions (e.g. nuclei 3.3.7,
semgrep 1.95.0). The version recorded in each ToolRun comes from the manifest;
the running binary's actual version is what the image installs. Reproducibility
requires building from the pinned manifests (see `docs/architecture/TOOL_SPEC.md`).

## Security

- `privileged/` is never started by default; policy must explicitly allow it.
- All containers run with `--read-only` (unless the tool needs writable fs),
  resource limits (`--cpus`, `--memory`, `--pids-limit`), and `--network`
  limited by policy (none < bridge < host).
