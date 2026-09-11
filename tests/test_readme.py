"""The README's sample output, held to the command the README itself names.

Nothing read the README before this file. Its quoted block reproduced byte for byte and
would have gone on doing so until 1 January 2027, when `--year`'s default moves and seven
dates in it become wrong with nobody having touched the repository. `site/build.py` pins
`DEMO_YEAR` for exactly that reason; the README did not, and the repository held the fix
one file over.

The command is read out of the README rather than written down here. A guard that carries
its own copy of the command proves the block matches *that* copy, which is not the claim
the README makes to a reader.
"""

from __future__ import annotations

import io
import re
import shlex
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path

import pytest

from auth_log_scan import cli

README = Path(__file__).resolve().parents[1] / "README.md"
#: The report's first line, which is what identifies its fenced block among the others.
BLOCK_MARKER = "== auth-log-scan report =="


def _readme() -> str:
    """The README with its line endings folded.

    It is committed CRLF and every process on the other side of this comparison writes LF,
    so a byte-for-byte read compares line endings and not content. Folding here is the
    deliberate half of that; the assertions below are then about the text.
    """
    return README.read_bytes().decode("utf-8").replace("\r\n", "\n")


def _fenced(text: str) -> list[str]:
    """Every fenced block, paired by walking the lines.

    Not by regex: the README opens some fences ```` ```bash ```` and some bare, and a
    pattern anchored on the bare form pairs a *closing* fence with the next *opening* one
    and captures the prose between two blocks. It found zero blocks and read as a missing
    section rather than as a broken reader.
    """
    blocks, current = [], None
    for line in text.split("\n"):
        if line.startswith("```"):
            if current is None:
                current = []
            else:
                blocks.append("".join(one + "\n" for one in current))
                current = None
        elif current is not None:
            current.append(line)
    assert current is None, "unclosed fence in the README"
    return blocks


def _sample_block(text: str) -> str:
    found = [one for one in _fenced(text) if one.startswith(BLOCK_MARKER)]
    assert len(found) == 1, f"expected exactly one {BLOCK_MARKER!r} block, found {len(found)}"
    return found[0]


def _quoted_command(text: str) -> list[str]:
    """The `auth-log-scan …` the README names immediately before its sample block."""
    cut = text.index("```\n" + BLOCK_MARKER)
    commands = re.findall(r"`(auth-log-scan [^`]+)`", text[:cut])
    assert commands, "the README must name the command its sample block is the output of"
    return shlex.split(commands[-1])[1:]


def _run(argv: list[str]) -> str:
    captured = io.StringIO()
    with redirect_stdout(captured):
        code = cli.main(argv)
    assert code == 0, f"{argv} exited {code}"
    return captured.getvalue()


def test_the_sample_block_is_what_the_readmes_own_quoted_command_prints():
    text = _readme()
    assert _run(_quoted_command(text)) == _sample_block(text)


@pytest.mark.parametrize("year", [2026, 2027, 2031])
def test_and_it_prints_the_same_block_whatever_year_the_reader_runs_it_in(monkeypatch, year):
    """The finding itself, stated as a property rather than as the shape of its fix.

    Without `--year` the block is a function of the clock. Asserting that the README names
    the flag would pass over any value; asserting the output does not move is the claim.
    """

    class _Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(year, 6, 1)

    monkeypatch.setattr(cli, "datetime", _Frozen)
    text = _readme()
    assert _run(_quoted_command(text)) == _sample_block(text)


def test_every_flag_the_parser_accepts_is_named_in_the_readme():
    """`--min-success-failures` was accepted by the CLI and documented nowhere.

    Read off the parser rather than listed here, so a flag added later arrives with this
    guard already pointing at it.
    """
    text = _readme()
    flags = {
        option
        for action in cli.build_parser()._actions
        for option in action.option_strings
        if option.startswith("--") and option != "--help"
    }
    assert flags, "the parser must expose long options for this guard to mean anything"
    assert {flag for flag in flags if flag not in text} == set()
