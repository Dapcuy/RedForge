#!/usr/bin/env python3
"""Deterministic e2e tool: verifies the mounted workspace and emits JSON.

Usage: e2e_tool.py <path-in-workspace>

Reads <path> (which must exist under the mounted /workspace), computes its
sha256, and prints a JSON line to stdout. This is used by the Docker E2E test
to prove workspace mounting + artifact/evidence capture work end-to-end.
"""
import hashlib
import json
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "expected one path argument"}), file=sys.stderr)
        return 2
    path = sys.argv[1]
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1
    digest = hashlib.sha256(data).hexdigest()
    print(json.dumps({"path": path, "size": len(data), "sha256": digest}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
