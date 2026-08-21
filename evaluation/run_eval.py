"""RedForge evaluation runner CLI.

Usage:
    python -m evaluation.run_eval \
        --target tests/fixtures/vuln_app \
        --kind source-dir \
        --benchmark evaluation/benchmarks/semgrep_vuln_app.json \
        --db path/to/previous-scan.db
    python -m evaluation.run_eval --list
    python -m evaluation.run_eval --summarize result.json

Without --db, it runs a fresh `redforge scan` and scores the findings from the
SQLite DB. With --db, it scores an existing scan.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from .metrics import EvalResult, load_benchmark, score_benchmark

ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS = Path(__file__).resolve().parent / "benchmarks"


def _read_findings(db_path: str) -> list[dict]:
    """Read findings rows from a RedForge SQLite DB."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT title, severity, confidence, status, affected_component, root_cause "
        "FROM findings"
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def _read_tool_runs(db_path: str) -> list[dict]:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT tool_name, status FROM tool_runs"
        ).fetchall()
    except sqlite3.Error:
        # Schema variation — table may be named differently.
        try:
            rows = con.execute("SELECT name, status FROM tool_runs").fetchall()
        except sqlite3.Error:
            rows = []
    con.close()
    return [dict(r) for r in rows]


def _run_fresh_scan(target: str, kind: str) -> str:
    """Run `redforge scan` into a temp DB and return the DB path."""
    tmp = tempfile.mkdtemp(prefix="redforge-eval-")
    db = str(Path(tmp) / "scan.db")
    cmd = [sys.executable, "-m", "core", "scan", "--target", target, "--kind", kind, "--db", db]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=ROOT)
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"scan failed: {proc.stderr[:500]}")
    # Keep the DB so the caller can inspect it, but register it for cleanup on
    # interpreter exit (best-effort).
    import atexit

    def _cleanup() -> None:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    atexit.register(_cleanup)
    return db


def _eval_one(benchmark_path: Path, target: str, kind: str, db: str | None) -> dict:
    bench = load_benchmark(benchmark_path)
    db = db or _run_fresh_scan(target, kind)
    findings = _read_findings(db)
    runs = _read_tool_runs(db)
    res: EvalResult = score_benchmark(bench, findings, runs)
    out = res.to_dict()
    out["target"] = target
    out["db"] = db
    out["missing_expectations"] = [
        {"component": c, "title": t}
        for c, t in bench.get("expected", [])
        if not any(
            c.lower() in str(f.get("affected_component", "")).lower()
            and t.lower() in str(f.get("title", "")).lower()
            for f in findings
        )
    ]
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="RedForge evaluation harness")
    ap.add_argument("--target", default="tests/fixtures/vuln_app", help="scan target")
    ap.add_argument("--kind", default="source-dir", choices=["source-dir", "url"], help="target kind")
    ap.add_argument("--benchmark", default=str(BENCHMARKS / "semgrep_vuln_app.json"), help="benchmark manifest")
    ap.add_argument("--db", default=None, help="score an existing scan DB (skip fresh scan)")
    ap.add_argument("--list", action="store_true", help="list available benchmarks")
    ap.add_argument("--json", action="store_true", help="emit JSON only")
    ap.add_argument("--out", default=None, help="write JSON result to file")
    args = ap.parse_args(argv)

    if args.list:
        for p in sorted(BENCHMARKS.glob("*.json")):
            print(p.name)
        return 0

    bench_path = Path(args.benchmark)
    if not bench_path.exists():
        bench_path = BENCHMARKS / args.benchmark
    out = _eval_one(bench_path, args.target, args.kind, args.db)

    if args.json or args.out:
        text = json.dumps(out, indent=2)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"wrote {args.out}")
        else:
            print(text)
        return 0

    print(f"Benchmark : {out['benchmark']}")
    print(f"Target    : {out['target']}")
    print(f"Expected  : {out['expected']}   Detected: {out['detected']}")
    print(f"Findings  : {out['total_findings']}   Confirmed: {out['confirmed']}")
    print("-" * 40)
    for k in ("detection_rate", "precision", "recall", "false_positive_rate",
              "validation_rate", "dedup_rate", "tool_success_rate"):
        print(f"{k:<22}: {out[k]}")
    if out["missing_expectations"]:
        print("-" * 40)
        print("MISSING:")
        for m in out["missing_expectations"]:
            print(f"  - {m['component']} :: {m['title']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())