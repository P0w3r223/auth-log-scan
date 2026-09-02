"""Assemble the published page by running the real scanner over the demo log.

Every figure on the page — the KPI numbers, the bars, the lanes, the flagged table, the
report block — is produced by ``parse`` and ``analyze``, the same code path the CLI uses.
Nothing is transcribed by hand and nothing is recomputed in the browser: the sliders move
between results this build already calculated, so the page cannot claim a detection the
scanner would not make.

The build is deterministic. The demo log's year is pinned (traditional syslog omits it) and
no build timestamp is embedded, which is what lets CI rebuild the page and compare it byte
for byte against the committed copy.
"""

from __future__ import annotations

import inspect
import json
from datetime import datetime, timedelta
from html import escape
from pathlib import Path
from string import Template
from typing import Dict, Iterable, List, Sequence, Tuple

from .. import analyze as analyze_module
from .. import config
from ..analyze import ScanResult, analyze
from ..parse import AuthEvent, EventType, parse_lines
from ..report import render_terminal
from . import charts

ASSET_DIR = Path(__file__).parent / "assets"
TEMPLATE_DIR = Path(__file__).parent / "templates"

# The demo log is dated, and traditional syslog omits the year — pinning it here is what
# keeps two builds of the same commit identical.
DEMO_YEAR = 2026
DEFAULT_THRESHOLD = config.BRUTE_FORCE_THRESHOLD
DEFAULT_WINDOW = int(config.BRUTE_FORCE_WINDOW.total_seconds())
# The values the sliders can take. Each window costs one full scan at build time; the
# threshold costs nothing, because the detector only ever compares it against the peak.
WINDOWS: Tuple[int, ...] = (15, 30, 60, 120, 300, 900, 3600)
THRESHOLDS: Tuple[int, ...] = tuple(range(3, 16))
# Lanes are one per source address. Beyond a handful the chart stops being readable, and
# the sources below the cut have single-digit failure counts.
MAX_LANES = 8
REPO_URL = "https://github.com/P0w3r223/auth-log-scan"


def _read(path: Path) -> str:
    """Read text with line endings normalised to LF.

    The template, the stylesheet and the script are checked out with whatever endings the
    platform's git prefers, and they flow straight into the page. Normalising here is what
    makes a Windows rebuild byte-identical to the Linux one CI compares against.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _kind(event: AuthEvent, breach_keys: set) -> str:
    if event.event == EventType.ACCEPTED:
        key = (event.source_ip, event.timestamp)
        return charts.BREACH if key in breach_keys else charts.ACCEPTED
    if event.event == EventType.INVALID_USER or event.invalid_user:
        return charts.INVALID
    return charts.FAILED


def _events_by_ip(events: Sequence[AuthEvent]) -> Dict[str, List[AuthEvent]]:
    grouped: Dict[str, List[AuthEvent]] = {}
    for event in events:
        grouped.setdefault(event.source_ip, []).append(event)
    return grouped


def _peaks_by_window(events: Sequence[AuthEvent], starts: Dict[str, datetime]) -> Dict[str, Dict]:
    """For every window length, what the detector's sliding pass found for each source.

    Scanning at threshold 1 returns a hit for every address that failed at all, which is
    precisely the peak count and peak position the detector would compare against any
    threshold. The browser then applies the threshold — one comparison, the same one in
    ``analyze`` — rather than re-implementing the window.
    """
    peaks: Dict[str, Dict] = {}
    for window in WINDOWS:
        result = analyze(events, threshold=1, window=timedelta(seconds=window))
        peaks[str(window)] = {
            hit.source_ip: {
                "peak": hit.max_in_window,
                "start": (hit.peak_start - starts[hit.source_ip]).total_seconds(),
            }
            for hit in result.brute_force
        }
    return peaks


def _verdict(peak: int, window: int, threshold: int) -> str:
    relation = "≥" if peak >= threshold else "<"
    return f"{peak} in {_window_label(window)} {relation} {threshold}"


def _window_label(seconds: int) -> str:
    """Seconds while the CLI's own unit still reads naturally, larger units past that."""
    if seconds >= 3600:
        return f"{seconds // 3600}h"
    if seconds > 120:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def _lanes(
    grouped: Dict[str, List[AuthEvent]],
    order: Sequence[str],
    peaks: Dict[str, Dict],
    threshold: int,
    window: int,
    breach_keys: set,
) -> List[charts.Lane]:
    lanes: List[charts.Lane] = []
    for ip in order:
        events = grouped[ip]
        start = events[0].timestamp
        span = (events[-1].timestamp - start).total_seconds()
        entry = peaks[str(window)].get(ip)
        peak = entry["peak"] if entry else 0
        lanes.append(
            charts.Lane(
                label=ip,
                marks=[
                    charts.Mark((event.timestamp - start).total_seconds(), _kind(event, breach_keys))
                    for event in events
                ],
                span=span,
                verdict=_verdict(peak, window, threshold),
                flagged=peak >= threshold,
                band_start=entry["start"] if entry else None,
                band_length=float(window) if entry else None,
            )
        )
    return lanes


def _timeline_lanes(grouped: Dict[str, List[AuthEvent]], order: Sequence[str],
                    origin: datetime, breach_keys: set) -> List[charts.Lane]:
    return [
        charts.Lane(
            label=ip,
            marks=[
                charts.Mark((event.timestamp - origin).total_seconds(), _kind(event, breach_keys))
                for event in grouped[ip]
            ],
            span=0.0,
        )
        for ip in order
    ]


def _hour_ticks(first: datetime, last: datetime) -> List[Tuple[float, str]]:
    """One tick per whole hour covered by the log, labelled HH:MM."""
    ticks: List[Tuple[float, str]] = []
    hour = first.replace(minute=0, second=0, microsecond=0)
    while hour <= last:
        if hour >= first:
            ticks.append(((hour - first).total_seconds(), hour.strftime("%H:%M")))
        hour += timedelta(hours=1)
    return ticks


def _slider_story(peaks: Dict[str, Dict], threshold: int, window: int) -> Dict[str, object]:
    """The two moves the sliders make, described from the results rather than from memory.

    Widening the window admits a source whose attempts are spread out; raising the
    threshold drops the weakest of the ones currently flagged. Both sentences on the page
    are built from these values, so they cannot outlive a change to the log.
    """
    at_default = {ip: entry["peak"] for ip, entry in peaks[str(window)].items()}
    flagged = {ip for ip, peak in at_default.items() if peak >= threshold}

    newcomer, widen_label, newcomer_peak = "", "", 0
    for candidate in WINDOWS:
        if candidate <= window:
            continue
        wider = {ip for ip, entry in peaks[str(candidate)].items() if entry["peak"] >= threshold}
        extra = sorted(wider - flagged)
        if extra:
            newcomer = extra[0]
            widen_label = _window_label(candidate)
            newcomer_peak = at_default.get(newcomer, 0)
            break

    weakest = min(flagged, key=lambda ip: (at_default[ip], ip)) if flagged else ""
    return {
        "newcomer": escape(newcomer),
        "newcomer_peak": newcomer_peak,
        "widen_label": widen_label,
        "weakest": escape(weakest),
        "weakest_peak": at_default[weakest] if weakest else 0,
    }


def _flagged_rows(lanes: Sequence[charts.Lane], grouped: Dict[str, List[AuthEvent]],
                  peaks: Dict[str, Dict], threshold: int, window: int) -> str:
    """Flagged sources in the order the CLI prints them: densest window first."""
    hits = [
        (lane, peaks[str(window)][lane.label])
        for lane in lanes
        if peaks[str(window)].get(lane.label, {}).get("peak", 0) >= threshold
    ]
    hits.sort(
        key=lambda pair: (
            pair[1]["peak"],
            sum(1 for e in grouped[pair[0].label] if e.event == EventType.FAILED),
        ),
        reverse=True,
    )

    rows: List[str] = []
    for lane, entry in hits:
        events = grouped[lane.label]
        failures = [e for e in events if e.event == EventType.FAILED]
        users = {e.user for e in failures}
        rows.append(
            "<tr class=\"flagged\">"
            f'<td class="ip">{escape(lane.label)}</td>'
            f'<td class="num">{entry["peak"]}</td>'
            f'<td class="num">{len(failures)}</td>'
            f'<td class="num">{len(users)}</td>'
            f"<td>{failures[0].timestamp:%H:%M:%S}</td>"
            f"<td>{failures[-1].timestamp:%H:%M:%S}</td>"
            "</tr>"
        )
    return "".join(rows)


def _suspicious_rows(result: ScanResult) -> str:
    if not result.suspicious_successes:
        return '<tr><td colspan="4" class="empty">None in this log.</td></tr>'
    return "".join(
        "<tr>"
        f'<td class="ip">{escape(hit.source_ip)}</td>'
        f'<td class="user">{escape(hit.user)}</td>'
        f"<td>{hit.timestamp:%H:%M:%S}</td>"
        f'<td class="num">{hit.prior_failures}</td>'
        "</tr>"
        for hit in result.suspicious_successes
    )


def _kpis(result: ScanResult, lines_read: int) -> str:
    flagged_failures = sum(hit.failures for hit in result.brute_force)
    share = flagged_failures / result.failed * 100 if result.failed else 0.0
    items = [
        ("Log lines read", f"{lines_read}", f"{result.total_events} recognised as sshd auth events; "
         "the rest are CRON, sudo and disconnects, skipped rather than guessed at", False),
        ("Failed logins", f"{result.failed}", f"{share:.0f}% of them come from the flagged sources "
         "below", False),
        ("Brute-force sources", f"{len(result.brute_force)}", f"at least {DEFAULT_THRESHOLD} "
         f"failures inside a {DEFAULT_WINDOW}s window", True),
        ("Accounts probed", f"{len(result.invalid_usernames)}", "usernames that do not exist on the "
         "host — the enumeration signature", False),
        ("Suspicious successes", f"{len(result.suspicious_successes)}", "an accepted login from an "
         "address that had already failed repeatedly", True),
    ]
    return "".join(
        '<li class="kpi">'
        f'<div class="kpi-value{" alert" if alert and value != "0" else ""}">{value}</div>'
        f'<div class="kpi-label">{label}</div>'
        f'<div class="kpi-note">{note}</div>'
        "</li>"
        for label, value, note, alert in items
    )


def _bars(pairs: Iterable[Tuple[str, int]]) -> List[charts.Bar]:
    return [charts.Bar(label=name, value=count) for name, count in pairs]


def _sliding_window_source() -> str:
    """The rule itself, read from ``analyze.py`` at build time rather than described."""
    return inspect.getsource(analyze_module._max_in_window).rstrip()


def render(log_path: Path) -> str:
    """Build the page from a log file. The only figures are the ones the scanner produces."""
    raw = _read(log_path).splitlines()
    events = list(parse_lines(raw, DEMO_YEAR))
    if not events:
        raise ValueError(f"{log_path} contains no recognised sshd auth events")

    result = analyze(events, threshold=DEFAULT_THRESHOLD,
                     window=timedelta(seconds=DEFAULT_WINDOW))
    grouped = _events_by_ip(sorted(events, key=lambda e: e.timestamp))
    starts = {ip: items[0].timestamp for ip, items in grouped.items()}
    peaks = _peaks_by_window(events, starts)

    failures_by_ip = {
        ip: sum(1 for e in items if e.event == EventType.FAILED) for ip, items in grouped.items()
    }
    order = sorted(grouped, key=lambda ip: (-failures_by_ip[ip], ip))[:MAX_LANES]
    breach_keys = {(hit.source_ip, hit.timestamp) for hit in result.suspicious_successes}

    origin, end = result.first_seen, result.last_seen
    timeline = charts.timeline_chart(
        _timeline_lanes(grouped, order, origin, breach_keys),
        _hour_ticks(origin, end),
        (end - origin).total_seconds(),
        "Authentication events by source address over the day",
    )
    lanes = _lanes(grouped, order, peaks, DEFAULT_THRESHOLD, DEFAULT_WINDOW, breach_keys)
    window_svg, geometry = charts.window_chart(
        lanes, "Failures per source with the densest window banded"
    )

    payload = {
        "thresholds": list(THRESHOLDS),
        "windows": list(WINDOWS),
        "defaults": {"threshold": DEFAULT_THRESHOLD, "window": DEFAULT_WINDOW},
        "geometry": {"x": geometry.x, "width": geometry.width, "spans": geometry.spans},
        "lanes": [
            {
                "ip": ip,
                "failures": failures_by_ip[ip],
                "users": len({e.user for e in grouped[ip] if e.event == EventType.FAILED}),
                "first": min(
                    (e.timestamp for e in grouped[ip] if e.event == EventType.FAILED),
                    default=grouped[ip][0].timestamp,
                ).strftime("%H:%M:%S"),
                "last": max(
                    (e.timestamp for e in grouped[ip] if e.event == EventType.FAILED),
                    default=grouped[ip][-1].timestamp,
                ).strftime("%H:%M:%S"),
            }
            for ip in order
        ],
        "peaks": peaks,
        "windowLabels": {str(w): _window_label(w) for w in WINDOWS},
    }

    values = {
        "styles": _read(ASSET_DIR / "styles.css").strip(),
        "script": _read(ASSET_DIR / "app.js").strip(),
        "date_label": f"{origin:%d %B %Y}",
        "host": escape(log_path.stem),
        "lines_read": len(raw),
        "events": result.total_events,
        "failed": result.failed,
        "accepted": result.accepted,
        "invalid_events": result.invalid_user_events,
        "span_hours": f"{(end - origin).total_seconds() / 3600:.1f}",
        "first_seen": f"{origin:%H:%M:%S}",
        "last_seen": f"{end:%H:%M:%S}",
        "kpis": _kpis(result, len(raw)),
        "timeline": timeline,
        "window_chart": window_svg,
        "flagged_rows": _flagged_rows(lanes, grouped, peaks, DEFAULT_THRESHOLD, DEFAULT_WINDOW),
        "flagged_count": len(result.brute_force),
        "suspicious_rows": _suspicious_rows(result),
        "probed_count": len(result.invalid_usernames),
        "probed": escape(", ".join(result.invalid_usernames)),
        "user_bars": charts.bar_chart(
            _bars(result.top_targeted_users), "Accounts by failed attempts", "attempts"
        ),
        "ip_bars": charts.bar_chart(
            _bars(result.top_source_ips), "Source addresses by failed logins", "failures"
        ),
        "report": escape(render_terminal(result)),
        "window_rule": escape(_sliding_window_source()),
        "threshold_default": DEFAULT_THRESHOLD,
        "window_default": DEFAULT_WINDOW,
        "window_default_label": _window_label(DEFAULT_WINDOW),
        "min_success_failures": config.SUSPICIOUS_SUCCESS_MIN_FAILURES,
        "threshold_min": THRESHOLDS[0],
        "threshold_max": THRESHOLDS[-1],
        "threshold_steps": len(THRESHOLDS) - 1,
        "threshold_index": THRESHOLDS.index(DEFAULT_THRESHOLD),
        "window_min_label": _window_label(WINDOWS[0]),
        "window_max_label": _window_label(WINDOWS[-1]),
        "window_steps": len(WINDOWS) - 1,
        "window_index": WINDOWS.index(DEFAULT_WINDOW),
        # "</" would close the surrounding <script> element early whatever the data means;
        # the escape is valid inside a JSON string and invisible to JSON.parse.
        "data": json.dumps(payload, separators=(",", ":"), sort_keys=True).replace("</", "<\\/"),
        **_slider_story(peaks, DEFAULT_THRESHOLD, DEFAULT_WINDOW),
        "repo": REPO_URL,
        "log_name": escape(log_path.name),
    }
    template = Template(_read(TEMPLATE_DIR / "index.html"))
    return template.substitute(values)


def build(log_path: Path, out_dir: Path) -> Path:
    """Render the page into ``out_dir`` and return the path written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    # GitHub Pages runs Jekyll unless told not to, which would drop nothing here today but
    # silently swallows any future file whose name starts with an underscore.
    (out_dir / ".nojekyll").write_text("", encoding="utf-8")
    target = out_dir / "index.html"
    # LF explicitly: the page is compared byte for byte, and a Windows build must not
    # produce a file that differs from a Linux one only in line endings.
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render(log_path))
    return target
