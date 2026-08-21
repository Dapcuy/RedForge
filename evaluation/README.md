# Evaluation Harness

Measure RedForge pipeline **quality**, not just exit codes.

## Structure

```
evaluation/
├── benchmarks/          # benchmark manifests (expected findings per target)
│   └── semgrep_vuln_app.json
├── metrics.py           # EvalResult + score_benchmark + summarize
└── run_eval.py          # CLI runner
```

## Metrics

| Metric | Definition |
|---|---|
| detection_rate | confirmed findings / expected |
| precision | confirmed / total findings |
| recall | same as detection_rate (binary expectations) |
| false_positive_rate | findings matching `negative` list / total |
| validation_rate | validated+confirmed / total |
| dedup_rate | 1 - (unique / total) |
| tool_success_rate | successful tool runs / total |

## Usage

```bash
# Run a fresh scan against a fixture and score it.
python -m evaluation.run_eval --target tests/fixtures/vuln_app --kind source-dir

# Score an existing scan DB (no re-scan).
python -m evaluation.run_eval --benchmark evaluation/benchmarks/semgrep_vuln_app.json \
    --db path/to/scan.db

# JSON output
python -m evaluation.run_eval --target tests/fixtures/vuln_app --kind source-dir --json

# List benchmarks
python -m evaluation.run_eval --list
```

## Benchmark manifest

```json
{
  "name": "semgrep_vuln_app",
  "target_kind": "source-dir",
  "expected": [
    ["app.py", "hardcoded"],
    ["app.py", "eval"]
  ],
  "negative": [
    ["app.py", "cryptographically secure"]
  ]
}
```

- `expected`: (component, title_substring) pairs that MUST be found as
  **confirmed** findings.
- `negative`: pairs that MUST NOT be raised (false-positive guard).

## Known limitation

Findings produced by the reference agents are `candidate` status; there is no
automatic candidate→confirmed validator yet. The harness therefore scores
agent-only scans as `detection_rate=0` until a validator is wired (see
Roadmap: Evidence → Finding Validation). Direct tool executions that produce
confirmed findings (e.g. the Semgrep Docker E2E) score normally.
