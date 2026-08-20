"""Run the RedForge dashboard (stdlib only, zero deps).

Usage:
    python -m web.dashboard [--port 8000] [--host 127.0.0.1]
"""
import argparse

from .app import serve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RedForge dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)

    # Seed with an empty finding list; findings come from a live run in practice.
    serve([], host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
