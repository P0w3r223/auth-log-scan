"""Detection logic over parsed auth events. Pure — takes events, returns a ``ScanResult``.

Three detectors:
  * brute-force  — a source IP with >= threshold failed logins inside a sliding time window
  * enumeration  — probing of usernames, especially non-existent ones ("invalid user")
  * suspicious   — an accepted login from an IP that had already failed many times earlier
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, List, Optional, Tuple

from . import config
from .parse import AuthEvent, EventType


@dataclass(frozen=True)
class BruteForceHit:
    source_ip: str
    failures: int  # total failed attempts from this IP
    max_in_window: int  # most failures within the sliding window
    window_seconds: int
    first_seen: datetime
    last_seen: datetime
    targeted_users: int


@dataclass(frozen=True)
class SuspiciousSuccess:
    source_ip: str
    user: str
    timestamp: datetime
    prior_failures: int


@dataclass
class ScanResult:
    total_events: int = 0
    failed: int = 0
    accepted: int = 0
    invalid_user_events: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    top_source_ips: List[Tuple[str, int]] = field(default_factory=list)  # (ip, failed count)
    top_targeted_users: List[Tuple[str, int]] = field(default_factory=list)  # (user, attempts)
    invalid_usernames: List[str] = field(default_factory=list)  # distinct usernames probed
    brute_force: List[BruteForceHit] = field(default_factory=list)
    suspicious_successes: List[SuspiciousSuccess] = field(default_factory=list)


def _max_in_window(sorted_times: List[datetime], window: timedelta) -> int:
    """Largest count of timestamps falling within any window-length span (input sorted asc)."""
    left = 0
    best = 0
    for right in range(len(sorted_times)):
        while sorted_times[right] - sorted_times[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def analyze(
    events: Iterable[AuthEvent],
    threshold: Optional[int] = None,
    window: Optional[timedelta] = None,
    min_success_failures: Optional[int] = None,
    top_n: Optional[int] = None,
) -> ScanResult:
    threshold = config.BRUTE_FORCE_THRESHOLD if threshold is None else threshold
    window = config.BRUTE_FORCE_WINDOW if window is None else window
    if min_success_failures is None:
        min_success_failures = config.SUSPICIOUS_SUCCESS_MIN_FAILURES
    top_n = config.TOP_N if top_n is None else top_n

    ordered = sorted(events, key=lambda e: e.timestamp)
    result = ScanResult(total_events=len(ordered))
    if not ordered:
        return result
    result.first_seen = ordered[0].timestamp
    result.last_seen = ordered[-1].timestamp

    failed_times_by_ip: dict[str, List[datetime]] = defaultdict(list)
    users_by_ip: dict[str, set] = defaultdict(set)
    failed_by_ip: Counter = Counter()
    targeted_users: Counter = Counter()
    invalid_usernames: set = set()
    failures_so_far: Counter = Counter()  # per IP, in time order (for suspicious success)

    for event in ordered:
        if event.event == EventType.FAILED:
            result.failed += 1
            failed_times_by_ip[event.source_ip].append(event.timestamp)
            users_by_ip[event.source_ip].add(event.user)
            failed_by_ip[event.source_ip] += 1
            targeted_users[event.user] += 1
            failures_so_far[event.source_ip] += 1
            if event.invalid_user:
                invalid_usernames.add(event.user)
        elif event.event == EventType.INVALID_USER:
            result.invalid_user_events += 1
            invalid_usernames.add(event.user)
        elif event.event == EventType.ACCEPTED:
            result.accepted += 1
            prior = failures_so_far[event.source_ip]
            if prior >= min_success_failures:
                result.suspicious_successes.append(
                    SuspiciousSuccess(event.source_ip, event.user, event.timestamp, prior)
                )

    for ip, times in failed_times_by_ip.items():
        times.sort()
        peak = _max_in_window(times, window)
        if peak >= threshold:
            result.brute_force.append(
                BruteForceHit(
                    source_ip=ip,
                    failures=len(times),
                    max_in_window=peak,
                    window_seconds=int(window.total_seconds()),
                    first_seen=times[0],
                    last_seen=times[-1],
                    targeted_users=len(users_by_ip[ip]),
                )
            )

    result.brute_force.sort(key=lambda h: (h.max_in_window, h.failures), reverse=True)
    result.suspicious_successes.sort(key=lambda s: s.prior_failures, reverse=True)
    result.top_source_ips = failed_by_ip.most_common(top_n)
    result.top_targeted_users = targeted_users.most_common(top_n)
    result.invalid_usernames = sorted(invalid_usernames)
    return result
