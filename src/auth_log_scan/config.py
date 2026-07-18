"""Central configuration: detection thresholds and report sizing. No I/O here — only constants.

Every tunable the detectors use lives here; the CLI can override each from a flag.
"""

from __future__ import annotations

from datetime import timedelta

# A source IP with at least this many failed logins inside BRUTE_FORCE_WINDOW is flagged.
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(seconds=60)

# An 'Accepted' login from an IP that already failed at least this many times earlier in the
# log is flagged as a suspicious success — a possible breach after brute forcing.
SUSPICIOUS_SUCCESS_MIN_FAILURES = 5

# Number of rows shown in the "top" tables.
TOP_N = 10
