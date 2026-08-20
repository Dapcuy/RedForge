# Runtimes — Execution Layer (Docker)

Per-domain runtime images. **Not one giant 500-tool image** — isolation and
maintainability win.

## Images

```
runtimes/
├── base/         # python 3.11-slim + node + go + curl/git (shared base)
├── web/          # httpx, nuclei, ffuf (built on base)
├── code/         # semgrep (built on base)
├── web3/         # foundry, slither, echidna, mythril (built on base)
├── privileged/   # nmap (needs host/network access; gated by policy)
└── test/         # tiny deterministic e2e tool (Docker E2E test only, not production)
```

## Build

```bash
docker compose build            # build all production images
docker compose build test       # build the tiny E2E test runtime
```

The `test` image (`redforge/test-runtime`) is **not** a production tool image;
it exists solely to prove workspace mounting + artifact/evidence capture inside
Docker via `tests/test_docker_e2e.py`.

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
