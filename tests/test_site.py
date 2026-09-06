import json
import re
from datetime import timedelta
from html.parser import HTMLParser
from pathlib import Path

import pytest

from auth_log_scan.analyze import analyze
from auth_log_scan.parse import parse_lines
from auth_log_scan.site import build as site

DEMO_LOG = Path(__file__).resolve().parents[1] / "sample" / "auth-demo.log"


def _payload(html: str) -> dict:
    match = re.search(r'<script type="application/json" id="scan-data">(.*?)</script>', html, re.DOTALL)
    assert match, "the page must carry the precomputed results it advertises"
    return json.loads(match.group(1))


@pytest.fixture(scope="module")
def page() -> str:
    return site.render(DEMO_LOG)


def test_page_flags_exactly_what_the_scanner_flags(page):
    events = list(parse_lines(DEMO_LOG.read_text(encoding="utf-8").splitlines(), site.DEMO_YEAR))
    expected = analyze(
        events,
        threshold=site.DEFAULT_THRESHOLD,
        window=timedelta(seconds=site.DEFAULT_WINDOW),
    )

    peaks = _payload(page)["peaks"][str(site.DEFAULT_WINDOW)]
    flagged = {ip for ip, entry in peaks.items() if entry["peak"] >= site.DEFAULT_THRESHOLD}
    assert flagged == {hit.source_ip for hit in expected.brute_force}
    for hit in expected.brute_force:
        assert peaks[hit.source_ip]["peak"] == hit.max_in_window


def test_every_slider_position_has_a_precomputed_result(page):
    payload = _payload(page)
    assert set(payload["peaks"]) == {str(window) for window in site.WINDOWS}
    assert payload["defaults"]["window"] in payload["windows"]
    assert payload["defaults"]["threshold"] in payload["thresholds"]
    # Each lane the browser may redraw needs its own scale and a group to redraw into.
    for lane in payload["lanes"]:
        assert lane["ip"] in payload["geometry"]["spans"]
        assert f'data-row="{lane["ip"]}"' in page or lane["ip"] in page


def test_page_is_deterministic():
    assert site.render(DEMO_LOG) == site.render(DEMO_LOG)


def test_untrusted_log_fields_are_escaped(tmp_path):
    # Usernames and addresses are attacker-chosen; a log must not be able to inject markup.
    payload = "<script>alert(1)</script>"
    log = tmp_path / "hostile.log"
    log.write_text(
        "\n".join(
            f"Mar 14 04:02:{second:02d} web01 sshd[{2000 + second}]: Failed password for "
            f"invalid user {payload} from 203.0.113.9 port {40000 + second} ssh2"
            for second in range(6)
        )
        + "\n",
        encoding="utf-8",
    )

    html = site.render(log)
    assert payload not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_build_writes_a_pages_ready_directory(tmp_path):
    written = site.build(DEMO_LOG, tmp_path)
    assert written == tmp_path / "index.html"
    assert (tmp_path / ".nojekyll").exists()
    # The published page is diffed byte for byte by CI, so line endings are not the OS's
    # to choose.
    assert b"\r\n" not in written.read_bytes()


def test_crlf_input_does_not_change_the_page(tmp_path):
    # A Windows checkout hands the build CRLF files. The page is diffed byte for byte, so
    # the line endings of the inputs must not reach the output.
    crlf = tmp_path / "crlf.log"
    crlf.write_bytes(DEMO_LOG.read_bytes().replace(b"\n", b"\r\n"))
    assert site.render(crlf) == site.render(DEMO_LOG).replace(DEMO_LOG.name, crlf.name)


def test_every_table_scrolls_inside_its_own_box(page):
    # The flagged table's six columns hold monospace addresses and timestamps that will not
    # wrap, so it is ~474px wide however narrow the screen is. Unwrapped it took the page
    # with it: 494px of content in a 375px viewport, i.e. 119px of horizontal scroll on a
    # phone. The container has to be there for every table, not only the one that was
    # measured overflowing — the other fits today at 335px only because of what this log
    # happens to contain.
    class _Tables(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.stack: list[str] = []
            self.unwrapped = 0
            self.tables = 0

        def handle_starttag(self, tag, attrs):
            if tag == "table":
                self.tables += 1
                if "table-wrap" not in self.stack:
                    self.unwrapped += 1
            if tag == "div":
                self.stack.append(dict(attrs).get("class", ""))

        def handle_endtag(self, tag):
            if tag == "div" and self.stack:
                self.stack.pop()

    parser = _Tables()
    parser.feed(page)
    assert parser.tables > 0, "the page is supposed to publish tables"
    assert parser.unwrapped == 0, f"{parser.unwrapped} table(s) can drag the page sideways"
    # The wrapper is inert without the rule that makes it scroll.
    styles = (Path(site.ASSET_DIR) / "styles.css").read_text(encoding="utf-8")
    assert re.search(r"\.table-wrap\s*\{[^}]*overflow-x:\s*auto", styles)


def test_render_refuses_a_log_it_recognises_nothing_in(tmp_path):
    log = tmp_path / "empty.log"
    log.write_text("Mar 14 04:02:00 web01 CRON[1]: session opened for user root\n", encoding="utf-8")
    with pytest.raises(ValueError):
        site.render(log)


# --------------------------------------------------------------------------------------
# SC 1.4.11 on the timeline marks — `0007` §5 clause 1 read at the usage site.
#
# Four pairs on this page failed 3:1 when this was written, and nothing could see them: every
# sweep before it measured a token against the *page's* ground, and these marks are not drawn
# on the page. `.chart .lane` fills with `--surface`, the window band is emitted over the lane
# at the same y and height, and the event marks are emitted after the band and sit on it. So a
# mark's ground is another element the same stylesheet paints, and the only way to know it is
# to composite in paint order.
# --------------------------------------------------------------------------------------

def _srgb(hex_colour: str) -> tuple[float, float, float]:
    digits = hex_colour.strip().lstrip("#")
    if len(digits) == 3:
        digits = "".join(c * 2 for c in digits)
    return tuple(int(digits[i:i + 2], 16) / 255 for i in (0, 2, 4))


def _luminance(rgb: tuple[float, float, float]) -> float:
    channels = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def _contrast(a: str, b: str) -> float:
    la, lb = _luminance(_srgb(a)), _luminance(_srgb(b))
    lighter, darker = max(la, lb), min(la, lb)
    return (lighter + 0.05) / (darker + 0.05)


def _over(top: str, bottom: str, alpha: float) -> str:
    """`top` at `alpha` composited over an opaque `bottom`, as the browser does it."""
    mixed = [round(255 * (t * alpha + b * (1 - alpha)))
             for t, b in zip(_srgb(top), _srgb(bottom), strict=True)]
    return "#" + "".join(f"{c:02x}" for c in mixed)


def _palettes(css: str) -> dict[str, dict[str, str]]:
    """Light and dark custom properties, dark starting as a copy of light."""
    dark_block = re.search(
        r"@media[^{]*prefers-color-scheme\s*:\s*dark[^{]*\{(.*?)\n\s*\}\s*\n", css, re.DOTALL)
    light = dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{3,8})",
                            css[:dark_block.start()] if dark_block else css))
    dark = dict(light)
    if dark_block:
        dark.update(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{3,8})", dark_block.group(1)))
    return {"light": light, "dark": dark}


def _painted(css: str, selector_pattern: str) -> list[tuple[str, str, float | None]]:
    """`(selector, token, opacity)` for every rule matching, read out of the stylesheet.

    **Derived rather than typed, and that is the whole point of it.** A first version listed
    the three marks its author had in mind; the stylesheet declares four — `.ev-accepted` is
    overridden by `.ev-accepted.breach`, which strokes `--danger` and is the mark this page's
    whole subject produces. The published page carries three of them. Listing the members of
    a set that lives in another file is the failure this repository's own record has now made
    seven times; a rule that joins the stylesheet joins this sweep with it.
    """
    found = []
    # The caller's pattern must carry exactly one group, naming the selector; the body is
    # this function's own. Without that the two call sites returned different shapes.
    for selector, body in re.findall(selector_pattern + r"\s*\{([^}]*)\}", css):
        token = re.search(r"(?:fill|stroke|background):\s*var\(--([\w-]+)\)", body)
        if not token:
            continue
        alpha = re.search(r"opacity:\s*([\d.]+)", body)
        found.append((selector, token.group(1), float(alpha.group(1)) if alpha else None))
    assert found, f"no painted rule matched {selector_pattern!r}"
    return found


def test_every_timeline_mark_clears_three_to_one_on_the_band_it_is_drawn_on(page):
    """Both bands, both schemes, every mark — sixteen pairs, and the set is not typed here.

    Five failed before this was written, all in the light scheme: `ev-accepted` on the window
    band at 2.81:1, and all four marks on the *flagged* band at 2.69, 2.70, 2.28 and 2.92. The
    flagged band is the one no earlier pass measured at all, because the reasoning had been
    about `--accent-soft` and that band paints `--danger`.

    **Everything the arithmetic needs is read out of the stylesheet** — which rules are marks,
    which token each paints, and every opacity. A first version listed three marks and two
    literal opacities; the stylesheet declares four marks, and `.ev-failed { opacity: 0.7 }`
    put a mark at 2.51:1 while this computed 3.09:1 and passed. Both were the same defect:
    a set enumerated in one file that lives in another.

    Lowering a band's opacity to satisfy this is a legitimate answer; raising one past what
    the marks can carry is not, and that is the direction this fails in.
    """
    css = re.search(r"<style>(.*?)</style>", page, re.DOTALL).group(1)
    palettes = _palettes(css)
    bands = _painted(css, r"(\.chart (?:\.row\.flagged )?\.window-band)")
    marks = _painted(css, r"\.(ev-[\w.-]+)")
    assert len(bands) == 2, [b[0] for b in bands]
    assert len(marks) == 4, [m[0] for m in marks]

    failures = []
    for scheme, palette in palettes.items():
        for band_name, band_token, band_alpha in bands:
            band = _over(palette[band_token], palette["surface"], band_alpha or 1.0)
            for mark_name, mark_token, mark_alpha in marks:
                mark = (_over(palette[mark_token], band, mark_alpha) if mark_alpha
                        else palette[mark_token])
                ratio = _contrast(mark, band)
                if ratio < 3.0:
                    failures.append(f"{scheme} .{mark_name} on {band_name}: {ratio:.2f}:1")
    assert not failures, (
        "SC 1.4.11 asks 3:1 of a graphical object against what it is drawn on, and these "
        "marks are drawn on the band rather than on the page:\n  " + "\n  ".join(failures)
    )


def test_the_bands_are_still_visible_against_the_lane_they_sit_on(page):
    """The other direction, so satisfying the check above by making a band invisible fails.

    A band at opacity 0 clears every mark trivially and tells the reader nothing. This does
    not pin a ratio the way the clause above does — no criterion applies to a decorative band
    — it pins that the band is distinguishable at all.
    """
    css = re.search(r"<style>(.*?)</style>", page, re.DOTALL).group(1)
    palettes = _palettes(css)
    for scheme, palette in palettes.items():
        for name, token, alpha in _painted(css, r"(\.chart (?:\.row\.flagged )?\.window-band)"):
            band = _over(palette[token], palette["surface"], alpha or 1.0)
            assert band.lower() != palette["surface"].lower(), (
                f"the {scheme} {name} composites to the lane's own colour, so it marks nothing"
            )
