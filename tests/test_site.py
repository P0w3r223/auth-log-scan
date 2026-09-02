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
    match = re.search(r'<script type="application/json" id="scan-data">(.*?)</script>', html, re.S)
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
