"""Render a ``ScanResult`` as a terminal report or a JSON-serialisable dict. No detection here."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from .analyze import ScanResult


def _fmt_ts(ts: Optional[datetime]) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "-"


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """Fixed-width text table (stdlib only). Integer columns are right-aligned."""
    ncols = len(headers)
    right = [len(rows) > 0 and all(isinstance(r[i], int) for r in rows) for i in range(ncols)]
    str_rows = [[str(c) for c in r] for r in rows]
    widths = [
        max([len(str(headers[i]))] + [len(r[i]) for r in str_rows]) for i in range(ncols)
    ]

    def fmt(cells: Sequence[str], header: bool = False) -> str:
        parts = [
            cells[i].rjust(widths[i]) if right[i] and not header else cells[i].ljust(widths[i])
            for i in range(ncols)
        ]
        return "  ".join(parts).rstrip()

    lines = [fmt([str(h) for h in headers], header=True), "  ".join("-" * w for w in widths)]
    lines += [fmt(r) for r in str_rows]
    return "\n".join(lines)


def render_terminal(result: ScanResult) -> str:
    out: List[str] = []
    out.append("== auth-log-scan report ==")
    out.append(f"events parsed : {result.total_events}")
    out.append(f"time range    : {_fmt_ts(result.first_seen)} .. {_fmt_ts(result.last_seen)}")
    out.append(
        f"failed / accepted / invalid-user : "
        f"{result.failed} / {result.accepted} / {result.invalid_user_events}"
    )
    out.append("")

    out.append(f"[!] brute-force sources ({len(result.brute_force)})")
    if result.brute_force:
        rows = [
            [h.source_ip, h.max_in_window, h.window_seconds, h.failures, h.targeted_users,
             _fmt_ts(h.first_seen), _fmt_ts(h.last_seen)]
            for h in result.brute_force
        ]
        out.append(
            _table(["source_ip", "max/win", "win(s)", "total", "users", "first", "last"], rows)
        )
    else:
        out.append("  none")
    out.append("")

    out.append(f"[!] suspicious successes ({len(result.suspicious_successes)})")
    if result.suspicious_successes:
        rows = [
            [s.source_ip, s.user, _fmt_ts(s.timestamp), s.prior_failures]
            for s in result.suspicious_successes
        ]
        out.append(_table(["source_ip", "user", "when", "prior_fails"], rows))
    else:
        out.append("  none")
    out.append("")

    out.append("top attacked usernames")
    if result.top_targeted_users:
        out.append(_table(["user", "attempts"], [[u, c] for u, c in result.top_targeted_users]))
    else:
        out.append("  none")
    out.append("")

    out.append("top source IPs by failures")
    if result.top_source_ips:
        out.append(_table(["source_ip", "failures"], [[ip, c] for ip, c in result.top_source_ips]))
    else:
        out.append("  none")
    out.append("")

    probed = ", ".join(result.invalid_usernames) if result.invalid_usernames else "none"
    out.append(f"invalid usernames probed ({len(result.invalid_usernames)}): {probed}")
    return "\n".join(out)


def to_json_dict(result: ScanResult) -> Dict[str, Any]:
    return {
        "summary": {
            "events_parsed": result.total_events,
            "first_seen": result.first_seen.isoformat() if result.first_seen else None,
            "last_seen": result.last_seen.isoformat() if result.last_seen else None,
            "failed": result.failed,
            "accepted": result.accepted,
            "invalid_user_events": result.invalid_user_events,
        },
        "brute_force": [
            {
                "source_ip": h.source_ip,
                "failures": h.failures,
                "max_in_window": h.max_in_window,
                "window_seconds": h.window_seconds,
                "first_seen": h.first_seen.isoformat(),
                "last_seen": h.last_seen.isoformat(),
                "targeted_users": h.targeted_users,
            }
            for h in result.brute_force
        ],
        "suspicious_successes": [
            {
                "source_ip": s.source_ip,
                "user": s.user,
                "timestamp": s.timestamp.isoformat(),
                "prior_failures": s.prior_failures,
            }
            for s in result.suspicious_successes
        ],
        "top_targeted_users": [{"user": u, "attempts": c} for u, c in result.top_targeted_users],
        "top_source_ips": [{"source_ip": ip, "failures": c} for ip, c in result.top_source_ips],
        "invalid_usernames": result.invalid_usernames,
    }
