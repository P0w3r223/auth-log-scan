"""Parse OpenSSH authentication log lines into structured events. Pure — no I/O.

Targets the traditional syslog format used by ``/var/log/auth.log`` (Debian/Ubuntu) and
``/var/log/secure`` (RHEL):

    Mar 10 06:55:46 host sshd[1234]: Failed password for invalid user admin from 203.0.113.7 port 40222 ssh2

The traditional format omits the year, so the caller supplies it (see ``parse_line``).
Lines that are not recognised sshd auth events return ``None`` and are simply skipped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Iterable, Iterator, Optional


class EventType(str, Enum):
    FAILED = "failed_password"
    ACCEPTED = "accepted"
    INVALID_USER = "invalid_user"


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    event: EventType
    user: str
    source_ip: str
    invalid_user: bool = False
    port: Optional[int] = None


# syslog prefix: "Mon DD HH:MM:SS host sshd[pid]: <message>" — capture the time and message.
_SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)

_FAILED_RE = re.compile(
    r"^Failed password for (?:(?P<invalid>invalid user) )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_ACCEPTED_RE = re.compile(
    r"^Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_INVALID_RE = re.compile(
    r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?"
)

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}


def _parse_timestamp(mon: str, day: str, time_str: str, year: int) -> Optional[datetime]:
    month = _MONTHS.get(mon)
    if month is None:
        return None
    hour, minute, second = (int(part) for part in time_str.split(":"))
    try:
        return datetime(year, month, int(day), hour, minute, second)
    except ValueError:
        return None


def parse_line(line: str, year: int) -> Optional[AuthEvent]:
    """Parse a single log line into an ``AuthEvent`` or ``None`` if it is not an sshd auth event."""
    prefix = _SYSLOG_RE.match(line.strip())
    if not prefix:
        return None
    timestamp = _parse_timestamp(prefix["mon"], prefix["day"], prefix["time"], year)
    if timestamp is None:
        return None
    msg = prefix["msg"]

    failed = _FAILED_RE.match(msg)
    if failed:
        return AuthEvent(
            timestamp,
            EventType.FAILED,
            failed["user"],
            failed["ip"],
            invalid_user=failed["invalid"] is not None,
            port=int(failed["port"]),
        )

    accepted = _ACCEPTED_RE.match(msg)
    if accepted:
        return AuthEvent(
            timestamp,
            EventType.ACCEPTED,
            accepted["user"],
            accepted["ip"],
            port=int(accepted["port"]),
        )

    invalid = _INVALID_RE.match(msg)
    if invalid:
        return AuthEvent(
            timestamp,
            EventType.INVALID_USER,
            invalid["user"],
            invalid["ip"],
            invalid_user=True,
            port=int(invalid["port"]) if invalid["port"] else None,
        )

    return None


def parse_lines(lines: Iterable[str], year: int) -> Iterator[AuthEvent]:
    """Parse an iterable of log lines, yielding only the recognised auth events."""
    for line in lines:
        event = parse_line(line, year)
        if event is not None:
            yield event
