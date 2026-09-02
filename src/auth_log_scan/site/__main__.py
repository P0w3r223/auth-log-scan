"""Build the published page: ``python -m auth_log_scan.site [--log PATH] [--out DIR]``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from .build import build

# Defaults are the repository's own layout, so the command needs no arguments in CI.
DEFAULT_LOG = Path("sample/auth-demo.log")
DEFAULT_OUT = Path("docs")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auth-log-scan-site",
        description="Render the demo page from a synthetic auth log.",
    )
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG, help=f"log to scan (default {DEFAULT_LOG})")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help=f"output directory (default {DEFAULT_OUT})")
    args = parser.parse_args(argv)

    try:
        written = build(args.log, args.out)
    except (OSError, ValueError) as exc:
        print(f"error: cannot build the page: {exc}", file=sys.stderr)
        return 1
    print(f"[page written to {written}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
