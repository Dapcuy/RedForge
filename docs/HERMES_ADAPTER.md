# Hermes Adapter — Live Bridge Contract

Hermes (or any LLM platform) is **one possible brain**, never the core. The
adapter maps structured input from an external brain onto RedForge's Agent
interface. It never exposes shell access or the runtime.

## EmitRequest JSON contract

An external brain pushes a JSON object describing what it wants RedForge to do:

```json
{
  "agent": "hermes",
  "observations": [
    {"content": "server: nginx", "kind": "fingerprint"}
  ],
  "decisions": [
    {"action": "run-tool", "rationale": "profile the target"}
  ],
  "tool_requests": [
    {"capability": "technology-detection", "arguments": {"u": "http://example.com"}},
    {"capability": "vulnerability-scanning", "arguments": {}}
  ],
  "finding_candidates": [
    {
      "title": "nginx outdated",
      "severity": "medium",
      "confidence": "low",
      "affected_component": "http://example.com",
      "root_cause": "server version",
      "evidence_refs": []
    }
  ]
}
```

- `tool_requests[].capability` is resolved by the Tool Registry through Policy
  (fail-closed). The brain never names a host path or a Docker command.
- `finding_candidates` are **hypotheses**; the Finding engine marks them
  `candidate` until validated/confirmed.
- Unknown fields are ignored (forward-compatible).

## Usage

```bash
# Hermes drives a scan via an inline emit payload
redforge scan --target http://127.0.0.1:9 --kind url \
  --agent hermes --emit '{"tool_requests":[{"capability":"technology-detection"}]}'

# ...or from a JSON file
redforge scan --target http://127.0.0.1:9 --kind url \
  --agent hermes --emit emit.json
```

## Flow

```
External brain (Hermes)
  -> EmitRequest JSON
  -> HermesAgent.parse_emit_request -> AgentResult
  -> Dispatcher -> ToolRequest (workspace_id opaque, no host paths)
  -> PolicyEngine (scope, network, limits) -> ToolRegistry -> DockerRuntime
  -> Artifact -> Evidence -> Finding (candidate)
```
