# Runtime Specification — v0.1

> Status: **Draft (Phase 0)**.

## 1. Purpose

The Runtime layer executes tools in an isolated, consistent environment. **The platform never talks to Docker directly** — agents and skills go through a Runtime Interface, so the execution backend is swappable.

```
Agent ──▶ Tool Executor ──▶ Runtime Interface ──▶ Docker Runtime ──▶ Container
```

## 2. Runtime Interface (contract)

```python
class Runtime(Protocol):
    def run(self, tool: Tool, target: Target, ctx: RunContext) -> RunResult: ...
    def stop(self, run_id: str) -> None: ...
    def logs(self, run_id: str) -> Iterator[str]: ...
    def inspect(self, run_id: str) -> RunStatus: ...
```

- `run()` returns a `RunResult` with `exit_code`, `stdout`, `stderr`, `artifacts`.
- Tool output is always normalized to **JSON** for downstream evidence capture.

## 3. MVP backend: Docker

- `DockerRuntime` implements the interface via `docker` / docker-py.
- Image strategy: **per-domain runtimes, not one giant image.**

```
runtime/
├── base/         # shared OS + python/node/go + common libs
├── web/          # httpx, nuclei, ffuf, browser
├── code/         # semgrep, language runtimes, dependency analyzers
├── web3/         # foundry, slither, echidna, mythril
└── privileged/   # tools needing host/network access (gated by policy)
```

## 4. Future backend

`PodmanRuntime` may be added later; it implements the same interface. **No skill or tool changes** when the backend changes.

## 5. Isolation & policy

- `privileged/` images are only runnable when `policy.allow_privileged_runtime` is true.
- Outbound access to external targets is gated by `policy.allow_external_targets`.
- `docker compose up -d` is the MVP bootstrap for the security runtime environment.

## 6. Bootstrap target (Phase 1)

```
docker compose up -d
 └── security runtime (python, node, go, nmap, nuclei, ffuf, semgrep, slither, foundry, echidna)
```
