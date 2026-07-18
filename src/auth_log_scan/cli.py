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
        "--min-success-failures", type=int, default=config.SUSPICIOUS_SUCCESS_MIN_FAILURES,
        help="prior failures from an IP before an accepted login is flagged suspicious "
        f"(default {config.SUSPICIOUS_SUCCESS_MIN_FAILURES})",
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


def _line_counter(iterable, counter: List[int]):
    """Pass lines through while counting them, so input can be streamed (not fully buffered)."""
    for line in iterable:
        counter[0] += 1
        yield line


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.threshold < 1 or args.window <= 0 or args.top < 0 or args.min_success_failures < 1:
        print(
            "error: --threshold and --min-success-failures must be >= 1, "
            "--window > 0, and --top >= 0",
            file=sys.stderr,
        )
        return 2

    year = args.year if args.year is not None else datetime.now().year

    seen = [0]  # lines read, counted as they stream through the parser
    try:
        if args.logfile == "-":
            events = list(parse_lines(_line_counter(sys.stdin, seen), year))
        else:
            with open(args.logfile, "r", encoding="utf-8", errors="replace") as handle:
                events = list(parse_lines(_line_counter(handle, seen), year))
    except OSError as exc:
        print(f"error: cannot read {args.logfile}: {exc}", file=sys.stderr)
        return 1

    if seen[0] and not events:
        print(
            f"warn: read {seen[0]} line(s) but recognized 0 sshd auth events "
            "— unsupported log format?",
            file=sys.stderr,
        )

    result = analyze(
        events,
        threshold=args.threshold,
        window=timedelta(seconds=args.window),
        min_success_failures=args.min_success_failures,
        top_n=args.top,
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
