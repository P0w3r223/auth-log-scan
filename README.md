# auth-log-scan

[![CI](https://github.com/P0w3r223/auth-log-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/P0w3r223/auth-log-scan/actions/workflows/ci.yml)

**Scan OpenSSH authentication logs for brute-force, username enumeration, and suspicious
logins** — a terminal report (and optional JSON) from `/var/log/auth.log`, no dependencies.

> Portfolio proof B2. Demonstrates Linux / security fundamentals and log analysis in Python
> (standard library only, pure/testable core) — covers the CISCO Ethical Hacker certificate.

## What it does

Reads an sshd auth log (file or stdin) and flags three things:

1. **Brute-force sources** — an IP with ≥ *threshold* failed logins inside a sliding time window.
2. **Username enumeration** — probing of accounts, especially non-existent ones (`invalid user`).
3. **Suspicious successes** — an `Accepted` login from an IP that had already failed many
   times earlier in the log (a possible breach after brute forcing).

## Setup

Python 3.11+; no runtime dependencies (standard library only).

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Linux: .venv/bin/python
pytest
```

## Usage

```bash
auth-log-scan sample/auth.log            # scan a file
cat /var/log/auth.log | auth-log-scan -  # read from stdin
python -m auth_log_scan sample/auth.log  # equivalent module form

# tune the detectors and export JSON:
auth-log-scan /var/log/auth.log -t 8 -w 120 --json findings.json
```

Options: `-t/--threshold` (default 5), `-w/--window` seconds (60), `--top` rows (10),
`--year` for timestamps that omit it (default: current year), `--json PATH` (`-` for stdout).

## Sample output

Running against the bundled synthetic log (`sample/auth.log`):

```
== auth-log-scan report ==
events parsed : 20
time range    : 2026-03-10 06:54:59 .. 2026-03-10 08:00:00
failed / accepted / invalid-user : 13 / 3 / 4

[!] brute-force sources (2)
source_ip      max/win  win(s)  total  users  first                last
-------------  -------  ------  -----  -----  -------------------  -------------------
203.0.113.7          7      60      7      5  2026-03-10 06:55:01  2026-03-10 06:55:13
198.51.100.23        6      60      6      1  2026-03-10 07:10:00  2026-03-10 07:10:10

[!] suspicious successes (1)
source_ip      user    when                 prior_fails
-------------  ------  -------------------  -----------
198.51.100.23  deploy  2026-03-10 07:10:12            6

top attacked usernames
user      attempts
--------  --------
deploy           6
root             3
admin            1
oracle           1
postgres         1
test             1

top source IPs by failures
source_ip      failures
-------------  --------
203.0.113.7           7
198.51.100.23         6

invalid usernames probed (4): admin, oracle, postgres, test
```

## Detections & methodology

- **Brute-force** uses a *sliding window*, not a naïve total: it reports the peak number of
  failures from an IP within any `window`-length span, so slow, spread-out noise is not
  mistaken for an attack.
- **Enumeration** counts attempts per username and collects every account probed via
  `invalid user`, the classic reconnaissance signature.
- **Suspicious success** only counts failures that occurred *before* the accepted login (the
  log is processed in time order), so a normal login that happens to precede later failures
  is not flagged.

The parser (`parse.py`) and detectors (`analyze.py`) are pure functions with no I/O; all
file/stdin handling lives in `cli.py`. That split is what makes the 24 unit tests possible
without touching a real log.

## Limitations

Deliberately a focused proof, not an IDS:

- **OpenSSH + traditional syslog format** (`auth.log` / `secure`). journald/ISO-8601
  timestamps and other daemons are out of scope.
- **The traditional format omits the year** — supplied via `--year` (default: current year).
- **Stateless, single-file** analysis (no persistence, no live tailing, IPv4/IPv6 treated as
  opaque source strings).
- The bundled `sample/auth.log` is **synthetic**, using RFC 5737 documentation IP ranges.

## License

MIT — see [LICENSE](LICENSE).
