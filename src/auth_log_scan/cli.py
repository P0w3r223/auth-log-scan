"""Command-line entry point: read an auth log (file or stdin), scan it, print a report.

This module holds the only I/O in the project; parsing, analysis, and rendering are pure.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from typing import List, Optional

from . import config
from .analyze import analyze
from .parse import parse_lines
from .report import render_terminal, to_json_dict


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auth-log-scan",
        description="Scan an OpenSSH auth log for brute-force, user enumeration, "
        "and suspicious logins.",
    )
    parser.add_argument(
        "logfile", nargs="?", default="-", help="path to the auth log, or '-' for stdin (default)"
    )
    parser.add_argument(
        "-t", "--threshold", type=int, default=config.BRUTE_FORCE_THRESHOLD,
        help=f"failed logins per IP within the window to flag (default {config.BRUTE_FORCE_THRESHOLD})",
    )
    parser.add_argument(
        "-w", "--window", type=int, default=int(config.BRUTE_FORCE_WINDOW.total_seconds()),
        help=f"brute-force window in seconds (default {int(config.BRUTE_FORCE_WINDOW.total_seconds())})",
    )
    parser.add_argument(
        "--top", type=int, default=config.TOP_N, help=f"rows in the top tables (default {config.TOP_N})"
    )
    parser.add_argument(
        "--year", type=int, default=None,
        help="year for syslog timestamps that omit it (default: current year)",
    )
    parser.add_argument(
        "--json", metavar="PATH", default=None,
        help="also write the report as JSON to PATH ('-' for stdout)",
    )
    return parser


def _read_lines(path: str) -> List[str]:
    if path == "-":
        return sys.stdin.read().splitlines()
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read().splitlines()


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    year = args.year if args.year is not None else datetime.now().year

    try:
        lines = _read_lines(args.logfile)
    except OSError as exc:
        print(f"error: cannot read {args.logfile}: {exc}", file=sys.stderr)
        return 1

    events = list(parse_lines(lines, year))
    result = analyze(
        events, threshold=args.threshold, window=timedelta(seconds=args.window), top_n=args.top
    )

    print(render_terminal(result))

    if args.json is not None:
        payload = json.dumps(to_json_dict(result), indent=2)
        if args.json == "-":
            print(payload)
        else:
            try:
                with open(args.json, "w", encoding="utf-8") as handle:
                    handle.write(payload + "\n")
            except OSError as exc:
                print(f"error: cannot write JSON to {args.json}: {exc}", file=sys.stderr)
                return 1
            print(f"[json written to {args.json}]", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
