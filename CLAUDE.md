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
sample/auth.log  # synthetic log (RFC 5737 documentation IPs) for the demo + docs
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
```

<!-- code-review-graph MCP tools -->
## MCP Tools: code-review-graph

**IMPORTANT: This project has a knowledge graph. ALWAYS use the
code-review-graph MCP tools BEFORE using Grep/Glob/Read to explore
the codebase.** The graph is faster, cheaper (fewer tokens), and gives
you structural context (callers, dependents, test coverage) that file
scanning cannot.

### When to use graph tools FIRST

- **Exploring code**: `semantic_search_nodes_tool` or `query_graph_tool` instead of Grep
- **Understanding impact**: `get_impact_radius_tool` instead of manually tracing imports
- **Code review**: `detect_changes_tool` + `get_review_context_tool` instead of reading entire files
- **Finding relationships**: `query_graph_tool` with callers_of/callees_of/imports_of/tests_for
- **Architecture questions**: `get_architecture_overview_tool` + `list_communities_tool`

Fall back to Grep/Glob/Read **only** when the graph doesn't cover what you need.

### Key Tools

| Tool | Use when |
| ------ | ---------- |
| `detect_changes_tool` | Reviewing code changes — gives risk-scored analysis |
| `get_review_context_tool` | Need source snippets for review — token-efficient |
| `get_impact_radius_tool` | Understanding blast radius of a change |
| `get_affected_flows_tool` | Finding which execution paths are impacted |
| `query_graph_tool` | Tracing callers, callees, imports, tests, dependencies |
| `semantic_search_nodes_tool` | Finding functions/classes by name or keyword |
| `get_architecture_overview_tool` | Understanding high-level codebase structure |
| `refactor_tool` | Planning renames, finding dead code |

### Workflow

1. No hooks installed — run `code-review-graph update` after code changes.
2. Use `detect_changes_tool` for code review.
3. Use `get_affected_flows_tool` to understand impact.
4. Use `query_graph_tool` pattern="tests_for" to check coverage.
