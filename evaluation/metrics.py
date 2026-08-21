"""RedForge Evaluation Harness — measure pipeline QUALITY, not just exit codes.

Metrics:
- detection_rate  : confirmed findings / expected findings
- precision       : confirmed findings / total findings
- recall          : confirmed findings / expected findings (== detection_rate
                    when there are no unconfirmed expectations)
- false_positive_rate: rejected (or false-positive) findings / total findings
- validation_rate : findings with status validated or confirmed / total
- dedup_rate      : (total - unique) / total findings
- tool_success_rate: successful tool runs / total tool runs

A benchmark declares:
    expected:  list of (component, title_substring) that MUST be detected
    negative :  list of (component, title_substring) that MUST NOT be raised
                (guards against regression / false positives)

Run:
    python -m evaluation.run_eval benchmarks/semgrep_vuln_app.json
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class EvalResult:
    """Aggregated metrics for one benchmark run."""

    benchmark: str
    expected: int = 0
    detected: int = 0
    false_positives: int = 0
    total_findings: int = 0
    confirmed: int = 0
    validated: int = 0
    unique_findings: int = 0
    tool_runs: int = 0
    tool_success: int = 0

    @property
    def detection_rate(self) -> float:
        return self.detected / self.expected if self.expected else 1.0

    @property
    def precision(self) -> float:
        return self.confirmed / self.total_findings if self.total_findings else 1.0

    @property
    def recall(self) -> float:
        return self.detection_rate

    @property
    def false_positive_rate(self) -> float:
        return self.false_positives / self.total_findings if self.total_findings else 0.0

    @property
    def validation_rate(self) -> float:
        return self.validated / self.total_findings if self.total_findings else 1.0

    @property
    def dedup_rate(self) -> float:
        if self.total_findings == 0:
            return 1.0
        return 1.0 - (self.unique_findings / self.total_findings)

    @property
    def tool_success_rate(self) -> float:
        return self.tool_success / self.tool_runs if self.tool_runs else 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark": self.benchmark,
            "expected": self.expected,
            "detected": self.detected,
            "false_positives": self.false_positives,
            "total_findings": self.total_findings,
            "confirmed": self.confirmed,
            "validated": self.validated,
            "unique_findings": self.unique_findings,
            "tool_runs": self.tool_runs,
            "tool_success": self.tool_success,
            "detection_rate": round(self.detection_rate, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "validation_rate": round(self.validation_rate, 4),
            "dedup_rate": round(self.dedup_rate, 4),
            "tool_success_rate": round(self.tool_success_rate, 4),
        }


def load_benchmark(path: str | Path) -> dict[str, Any]:
    """Load a benchmark manifest from JSON/YAML."""
    import yaml

    p = Path(path)
    if p.suffix in (".yaml", ".yml"):
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return json.loads(p.read_text(encoding="utf-8"))


def score_benchmark(
    benchmark: dict[str, Any],
    findings: list[dict[str, Any]],
    tool_runs: list[dict[str, Any]] | None = None,
) -> EvalResult:
    """Score a set of findings against a benchmark manifest."""
    res = EvalResult(benchmark=benchmark.get("name", str(Path(str(benchmark.get("source", "?"))).stem)))

    expected = benchmark.get("expected", [])
    negative = benchmark.get("negative", [])
    res.expected = len(expected)

    # Normalize finding statuses.
    confirmed = [f for f in findings if str(f.get("status", "")).lower() in ("confirmed", "validated")]
    validated = [f for f in findings if str(f.get("status", "")).lower() in ("validated", "confirmed")]
    res.confirmed = len(confirmed)
    res.validated = len(validated)
    res.total_findings = len(findings)

    # Unique findings: dedupe by (affected_component, title) lowercased.
    seen: set[tuple[str, str]] = set()
    for f in findings:
        key = (
            str(f.get("affected_component", "")).lower(),
            str(f.get("title", "")).lower(),
        )
        seen.add(key)
    res.unique_findings = len(seen)

    # Expected detections: substring match on component+title of CONFIRMED findings.
    for comp, title_sub in expected:
        for f in confirmed:
            comp_hit = comp.lower() in str(f.get("affected_component", "")).lower()
            title_hit = title_sub.lower() in str(f.get("title", "")).lower()
            if comp_hit and title_hit:
                res.detected += 1
                break

    # Negative (must NOT be raised): any confirmed finding matching -> FP.
    for comp, title_sub in negative:
        for f in confirmed:
            comp_hit = comp.lower() in str(f.get("affected_component", "")).lower()
            title_hit = title_sub.lower() in str(f.get("title", "")).lower()
            if comp_hit and title_hit:
                res.false_positives += 1

    # Tool runs.
    if tool_runs:
        res.tool_runs = len(tool_runs)
        res.tool_success = sum(1 for r in tool_runs if str(r.get("status", "")).lower() == "success")

    return res


def summarize(results: list[EvalResult]) -> dict[str, Any]:
    """Aggregate multiple benchmark runs into a summary."""
    if not results:
        return {"benchmarks": 0}
    return {
        "benchmarks": len(results),
        "avg_detection_rate": round(sum(r.detection_rate for r in results) / len(results), 4),
        "avg_precision": round(sum(r.precision for r in results) / len(results), 4),
        "avg_recall": round(sum(r.recall for r in results) / len(results), 4),
        "avg_false_positive_rate": round(sum(r.false_positive_rate for r in results) / len(results), 4),
        "avg_validation_rate": round(sum(r.validation_rate for r in results) / len(results), 4),
        "avg_dedup_rate": round(sum(r.dedup_rate for r in results) / len(results), 4),
        "avg_tool_success_rate": round(sum(r.tool_success_rate for r in results) / len(results), 4),
    }
