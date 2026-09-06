# CLAUDE.md — auth-log-scan

Guidance for Claude Code (and any contributor) working in this repository.

## What this project is
A command-line scanner that reads OpenSSH authentication logs (`/var/log/auth.log`,
`/var/log/secure`) and flags brute-force sources, username enumeration, and suspicious
logins, printing a terminal report (and optional JSON). Portfolio proof B2 — evidence of
Linux/security fundamentals and log analysis; covers the CISCO Ethical Hacker certificate.

## Architecture
```
src/auth_log_scan/
  config.py    # detection thresholds + report sizing (no I/O)
  parse.py     # sshd log line -> AuthEvent (pure regex parsing, no I/O)
  analyze.py   # AuthEvent list -> ScanResult (brute-force / enumeration / suspicious success)
  report.py    # ScanResult -> terminal tables and JSON dict (rendering only)
  cli.py       # the only I/O: read file/stdin, run the scan, print/export
  site/        # static page generator for GitHub Pages (not imported by the scanner)
    charts.py    # rows -> inline SVG (pure)
    build.py     # runs the real scanner over the demo log, renders docs/index.html
    templates/, assets/   # string.Template page, CSS, and the slider script
sample/auth.log       # synthetic log (RFC 5737 documentation IPs) for the demo + docs
sample/auth-demo.log  # larger synthetic log, scanned to build the published page
docs/            # the published page (generated; CI fails if it is stale or hand-edited)
tests/           # pytest
```

## Rules (do not violate)
- **Separate I/O from logic.** `parse`/`analyze`/`report` are pure and unit-tested; disk and
  stdin/stdout live only in `cli.py`.
- **No hardcoded thresholds.** Detection tunables live in `config.py`; the CLI overrides them.
- **Synthetic data only.** Any committed sample log uses RFC 5737 documentation IP ranges
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and invented usernames — never real logs.
- **Parse defensively.** Unrecognized lines (CRON, disconnects, other daemons) are skipped,
  never crash the scan.
- **Traditional syslog timestamps omit the year** — the year is supplied by the caller
  (`--year`, default: current year); keep parsing deterministic given its inputs.
- **The page never restates a finding.** Everything on `docs/index.html` is produced by
  `parse`/`analyze`; the browser only repeats the detector's own `peak >= threshold`
  comparison over results the build precomputed. No detection logic in JavaScript.
- **The page build is deterministic** — the demo log's year is pinned and no build
  timestamp is embedded, because CI diffs the rebuilt page against the committed one.
  Rebuild with `python -m auth_log_scan.site` and commit the result.

## Conventions
- English for code, comments, README, commit messages. Conventional Commits.
- No hardcoded values — configurable things live in `config.py`.
- Separate I/O from logic; pure functions are unit-tested.
- Interpreter: `.venv/Scripts/python.exe` (Python 3.12). Standard library only at runtime.

## How to run
```bash
.venv/Scripts/python -m pip install -r requirements.txt
pytest
auth-log-scan sample/auth.log            # or: python -m auth_log_scan sample/auth.log
cat /var/log/auth.log | auth-log-scan -   # read from stdin
python -m auth_log_scan.site              # rebuild docs/index.html from sample/auth-demo.log
```

## The published page

`docs/index.html` is one of twelve surfaces held to a single specification: ten house colour tokens
with pinned per-theme values, a dark override, six card-metadata tags, a profile back-link, a
result-shaped `h1`, and — since S4 — the rule that **every figure the surface prints is a figure
a committed artifact prints**, never a rounding and never a re-derivation. The spec is
`docs/audit/0007_divergence-and-the-page-spec.md` §5 in the private portfolio index, and
`tools/pagespec` there sweeps all twelve from the submodule working trees on every push.

That checker reads HTML and CSS, so it cannot see this repository's artifacts and cannot tell an
exempt page from one nobody built tiles for. What it structurally cannot carry lives in
`tests/test_site.py` — the other half of the carrier, and the reason `docs/adr/0004_what-carries-the-page-spec.md`
chose one checker plus local assertions over eleven vendored copies.

## Code intelligence

Two indexes exist over this repo, and which one is reachable depends on where the session started:

- `.codegraph/` — the `codegraph_explore` MCP tool, or `codegraph explore "<question>"` from a
  shell. Returns the relevant symbols' verbatim source plus the call paths between them, so it
  usually answers a "how does X work" or "what calls Y" question in one call. The CLI ships as
  `codegraph.cmd`, so from Git Bash it needs the extension — bare `codegraph` resolves only
  where PATHEXT applies.
- `.code-review-graph/` — its MCP server is declared in **this repository's** `.mcp.json`, so it
  loads when Claude Code runs with this directory as the working directory, and is simply absent
  when the session started in the private portfolio index one level up. When its tools are
  missing the CLI still works: `uvx code-review-graph <command>`.

**Neither index has a hook**, so both are only as fresh as the last manual update — and a graph
that predates the work you are looking at will answer confidently about code that is gone.
`codegraph.cmd status` reports the index's age; `codegraph.cmd sync` brings it forward, and
`uvx code-review-graph update` does the same for the other. Check before trusting either on a
question about recent changes.

Grep, Glob and Read stay correct whenever the question is about text rather than structure, or
when neither index is available.
