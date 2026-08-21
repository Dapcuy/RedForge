"""Tests for the evaluation harness metrics & scoring."""
import json

from evaluation.metrics import score_benchmark, summarize

BENCH = {
    "name": "test-bench",
    "expected": [
        ["app.py", "hardcoded"],
        ["app.py", "eval"],
        ["app.py", "shell"],
    ],
    "negative": [
        ["app.py", "cryptographically secure"],
    ],
}


def _finding(title, status="confirmed", component="app.py"):
    return {
        "title": title,
        "severity": "high",
        "confidence": "medium",
        "status": status,
        "affected_component": component,
        "root_cause": title,
    }


def test_perfect_detection():
    findings = [
        _finding("hardcoded password in app.py"),
        _finding("eval use in app.py"),
        _finding("shell=True subprocess in app.py"),
    ]
    res = score_benchmark(BENCH, findings)
    assert res.detection_rate == 1.0
    assert res.precision == 1.0
    assert res.false_positive_rate == 0.0
    assert res.dedup_rate == 0.0  # 3 unique


def test_missing_expectation():
    findings = [_finding("hardcoded password in app.py")]
    res = score_benchmark(BENCH, findings)
    assert res.detected == 1
    assert abs(res.detection_rate - 1 / 3) < 1e-6
    assert abs(res.recall - 1 / 3) < 1e-6


def test_false_positive_negative():
    findings = [_finding("cryptographically secure key found in app.py")]
    res = score_benchmark(BENCH, findings)
    assert res.false_positives == 1
    assert res.false_positive_rate == 1.0


def test_status_candidate_not_confirmed():
    findings = [_finding("eval use in app.py", status="candidate")]
    res = score_benchmark(BENCH, findings)
    assert res.confirmed == 0
    assert res.detection_rate == 0.0  # candidates don't count


def test_dedup_rate():
    findings = [
        _finding("eval use in app.py"),
        _finding("eval use in app.py"),  # duplicate
        _finding("hardcoded password in app.py"),
    ]
    res = score_benchmark(BENCH, findings)
    assert res.total_findings == 3
    assert res.unique_findings == 2
    assert round(res.dedup_rate, 4) == round(1 - 2 / 3, 4)


def test_tool_success_rate():
    runs = [
        {"tool_name": "semgrep", "status": "success"},
        {"tool_name": "nuclei", "status": "failed"},
    ]
    res = score_benchmark(BENCH, [], runs)
    assert res.tool_success_rate == 0.5


def test_summarize():
    a = score_benchmark(BENCH, [_finding("hardcoded password in app.py")])
    b = score_benchmark(BENCH, [_finding("hardcoded password in app.py")])
    s = summarize([a, b])
    assert s["benchmarks"] == 2
    assert s["avg_detection_rate"] == round(1 / 3, 4)


def test_load_benchmark_json(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps(BENCH), encoding="utf-8")
    from evaluation.metrics import load_benchmark
    assert load_benchmark(p)["name"] == "test-bench"
