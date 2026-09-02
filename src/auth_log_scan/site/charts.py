"""Charts as inline SVG — pure functions from rows to markup. No I/O, no detection.

SVG rather than an embedded image for three reasons that matter here: it inherits the
reader's colour scheme, so dark mode is not a second rendering; it stays sharp at any
size; and its text is real text, which a screen reader can read out.

Every mark carries its meaning in shape as well as colour — a failure is a filled dot, an
accepted login a ring, a probe of a non-existent account a diamond — so a figure survives
being read in greyscale.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html import escape
from typing import Dict, List, Sequence, Tuple

WIDTH = 720
_PAD = 12
_BAR_ROW = 26
_BAR_LABEL_WIDTH = 130
_BAR_VALUE_WIDTH = 62

_LANE_ROW = 34
_LANE_LABEL_WIDTH = 132
_LANE_VERDICT_WIDTH = 122
_LANE_TOP = 26

# Mark kinds. `breach` is an accepted login the scanner flagged as suspicious — the same
# shape as any other success, drawn in the alert colour, because it *is* a success: what
# makes it notable is what came before it.
FAILED = "failed"
INVALID = "invalid"
ACCEPTED = "accepted"
BREACH = "breach"


@dataclass(frozen=True)
class Bar:
    label: str
    value: int
    note: str | None = None  # e.g. "5 users", rendered after the value
    muted: bool = False


@dataclass(frozen=True)
class Mark:
    """One event on a lane, placed by its offset in seconds from the lane's own start."""

    offset: float
    kind: str = FAILED


@dataclass(frozen=True)
class Lane:
    """One source address: its events, the span they cover, and what the detector said."""

    label: str
    marks: Sequence[Mark]
    span: float  # seconds from the lane's first to its last event
    verdict: str = ""
    flagged: bool = False
    band_start: float | None = None  # offset of the densest window, when one is drawn
    band_length: float | None = None  # the window length itself, in seconds


@dataclass(frozen=True)
class LaneGeometry:
    """Where the plot area sits, so the browser can move a band without re-deriving it."""

    x: float
    width: float
    spans: Dict[str, float] = field(default_factory=dict)


def _text(value) -> str:
    return escape(str(value), quote=True)


def _svg(width: int, height: float, title: str, body: str, extra: str = "") -> str:
    return (
        f'<svg class="chart" viewBox="0 0 {width} {height:.0f}" width="{width}" '
        f'height="{height:.0f}" role="img" aria-label="{_text(title)}"{extra} '
        f'xmlns="http://www.w3.org/2000/svg">'
        f"<title>{_text(title)}</title>{body}</svg>"
    )


def bar_chart(bars: Sequence[Bar], title: str, unit: str) -> str:
    """Horizontal bars, longest first, each labelled with its value."""
    if not bars:
        return '<p class="empty">Nothing in this log.</p>'

    largest = max((bar.value for bar in bars), default=1) or 1
    plot_width = WIDTH - _BAR_LABEL_WIDTH - _BAR_VALUE_WIDTH
    height = len(bars) * _BAR_ROW + _PAD * 2

    parts: List[str] = []
    for index, bar in enumerate(bars):
        y = _PAD + index * _BAR_ROW
        width = max(1.0, bar.value / largest * plot_width)
        classes = "bar muted" if bar.muted else "bar"
        note = f"  {bar.note}" if bar.note else ""
        parts.append(
            f'<text class="row-label" x="{_BAR_LABEL_WIDTH - 8}" y="{y + 13}" '
            f'text-anchor="end">{_text(bar.label)}</text>'
            f'<rect class="{classes}" x="{_BAR_LABEL_WIDTH}" y="{y + 3}" '
            f'width="{width:.1f}" height="{_BAR_ROW - 9}" rx="2"></rect>'
            f'<text class="bar-value" x="{_BAR_LABEL_WIDTH + width + 6:.1f}" y="{y + 13}">'
            f"{bar.value}{_text(note)}</text>"
        )
    return _svg(WIDTH, height, f"{title} ({unit})", "".join(parts))


def _mark(x: float, y: float, kind: str) -> str:
    if kind in (ACCEPTED, BREACH):
        classes = "ev-accepted breach" if kind == BREACH else "ev-accepted"
        return f'<circle class="{classes}" cx="{x:.1f}" cy="{y:.1f}" r="4.5"></circle>'
    if kind == INVALID:
        return (
            f'<rect class="ev-invalid" x="{x - 3.2:.1f}" y="{y - 3.2:.1f}" width="6.4" '
            f'height="6.4" transform="rotate(45 {x:.1f} {y:.1f})"></rect>'
        )
    return f'<circle class="ev-failed" cx="{x:.1f}" cy="{y:.1f}" r="3"></circle>'


def timeline_chart(lanes: Sequence[Lane], ticks: Sequence[Tuple[float, str]], span: float,
                   title: str) -> str:
    """Every source on one shared clock — where in the day the pressure actually came from.

    A single axis for all lanes is the point: it shows that four bursts minutes long sit
    inside seven quiet hours, which per-lane axes would flatten away.
    """
    if not lanes:
        return '<p class="empty">Nothing in this log.</p>'

    plot_width = WIDTH - _LANE_LABEL_WIDTH - 24
    height = _LANE_TOP + len(lanes) * _LANE_ROW + 26
    scale = plot_width / max(span, 1.0)

    parts: List[str] = []
    baseline = _LANE_TOP + len(lanes) * _LANE_ROW
    for offset, label in ticks:
        x = _LANE_LABEL_WIDTH + offset * scale
        parts.append(
            f'<line class="lane-line" x1="{x:.1f}" x2="{x:.1f}" y1="{_LANE_TOP - 8}" '
            f'y2="{baseline}"></line>'
            f'<text class="axis" x="{x:.1f}" y="{baseline + 16}" text-anchor="middle">'
            f"{_text(label)}</text>"
        )

    for index, lane in enumerate(lanes):
        y = _LANE_TOP + index * _LANE_ROW + _LANE_ROW / 2
        parts.append(
            f'<text class="row-label" x="{_LANE_LABEL_WIDTH - 10}" y="{y + 4}" '
            f'text-anchor="end">{_text(lane.label)}</text>'
        )
        parts += [
            _mark(_LANE_LABEL_WIDTH + mark.offset * scale, y, mark.kind) for mark in lane.marks
        ]
    return _svg(WIDTH, height, title, "".join(parts))


def window_chart(lanes: Sequence[Lane], title: str) -> Tuple[str, LaneGeometry]:
    """One lane per source, each on **its own** clock, with the densest window banded.

    The shared clock of the timeline above cannot show this: a 60-second window is a third
    of a pixel wide across seven hours. Zooming each source to its own span is what makes
    the rule visible — the band is the window, the dots inside it are the count the
    threshold is compared against, and everything the detector decides is in that picture.

    Returns the markup and the plot geometry, so the browser can slide the band to another
    precomputed result without re-deriving the scale.
    """
    if not lanes:
        return '<p class="empty">Nothing in this log.</p>', LaneGeometry(0.0, 0.0)

    plot_width = WIDTH - _LANE_LABEL_WIDTH - _LANE_VERDICT_WIDTH
    height = _LANE_TOP + len(lanes) * _LANE_ROW + 12
    verdict_x = _LANE_LABEL_WIDTH + plot_width + 10

    parts: List[str] = []
    spans: Dict[str, float] = {}
    for index, lane in enumerate(lanes):
        span = max(lane.span, 1.0)
        spans[lane.label] = span
        scale = plot_width / span
        top = _LANE_TOP + index * _LANE_ROW
        centre = top + _LANE_ROW / 2
        row_class = "row flagged" if lane.flagged else "row"

        band = ""
        if lane.band_start is not None and lane.band_length is not None:
            band_x = _LANE_LABEL_WIDTH + lane.band_start * scale
            band_w = min(lane.band_length * scale, plot_width - lane.band_start * scale)
            band = (
                f'<rect class="window-band" data-band="{_text(lane.label)}" '
                f'x="{band_x:.1f}" y="{top + 4:.1f}" width="{max(band_w, 2.0):.1f}" '
                f'height="{_LANE_ROW - 12}" rx="3"></rect>'
            )

        marks = "".join(
            _mark(_LANE_LABEL_WIDTH + mark.offset * scale, centre, mark.kind)
            for mark in lane.marks
        )
        parts.append(
            f'<g class="{row_class}" data-row="{_text(lane.label)}">'
            f'<rect class="lane" x="{_LANE_LABEL_WIDTH}" y="{top + 4:.1f}" '
            f'width="{plot_width}" height="{_LANE_ROW - 12}" rx="3"></rect>'
            f"{band}"
            f'<line class="lane-line" x1="{_LANE_LABEL_WIDTH}" x2="{_LANE_LABEL_WIDTH + plot_width}" '
            f'y1="{centre:.1f}" y2="{centre:.1f}"></line>'
            f"{marks}"
            f'<text class="row-label" x="{_LANE_LABEL_WIDTH - 10}" y="{centre + 4:.1f}" '
            f'text-anchor="end">{_text(lane.label)}</text>'
            f'<text class="verdict" data-verdict="{_text(lane.label)}" x="{verdict_x:.1f}" '
            f'y="{centre + 4:.1f}">{_text(lane.verdict)}</text>'
            f"</g>"
        )

    markup = _svg(WIDTH, height, title, "".join(parts), extra=' id="window-chart"')
    return markup, LaneGeometry(x=float(_LANE_LABEL_WIDTH), width=float(plot_width), spans=spans)
