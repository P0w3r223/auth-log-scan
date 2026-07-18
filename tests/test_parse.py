from datetime import datetime

from auth_log_scan.parse import EventType, parse_line, parse_lines

YEAR = 2026


def test_parse_failed_password():
    line = "Mar 10 06:55:05 web01 sshd[2102]: Failed password for root from 203.0.113.7 port 40003 ssh2"
    event = parse_line(line, YEAR)
    assert event is not None
    assert event.event == EventType.FAILED
    assert event.user == "root"
    assert event.source_ip == "203.0.113.7"
    assert event.port == 40003
    assert event.invalid_user is False
    assert event.timestamp == datetime(2026, 3, 10, 6, 55, 5)


def test_parse_failed_for_invalid_user_sets_flag():
    line = "Mar 10 06:55:01 web01 sshd[2100]: Failed password for invalid user admin from 203.0.113.7 port 40001 ssh2"
    event = parse_line(line, YEAR)
    assert event.event == EventType.FAILED
    assert event.user == "admin"
    assert event.invalid_user is True


def test_parse_accepted_password_and_publickey():
    passwd = parse_line(
        "Mar 10 07:10:12 web01 sshd[2206]: Accepted password for deploy from 198.51.100.23 port 44007 ssh2",
        YEAR,
    )
    assert passwd.event == EventType.ACCEPTED
    assert passwd.user == "deploy"
    assert passwd.source_ip == "198.51.100.23"

    pubkey = parse_line(
        "Mar 10 06:54:59 web01 sshd[2001]: Accepted publickey for alice from 192.0.2.10 port 51000 ssh2",
        YEAR,
    )
    assert pubkey.event == EventType.ACCEPTED
    assert pubkey.user == "alice"


def test_parse_invalid_user_line():
    event = parse_line(
        "Mar 10 06:55:01 web01 sshd[2100]: Invalid user admin from 203.0.113.7 port 40001", YEAR
    )
    assert event.event == EventType.INVALID_USER
    assert event.user == "admin"
    assert event.invalid_user is True
    assert event.source_ip == "203.0.113.7"


def test_non_sshd_and_noise_lines_are_skipped():
    assert (
        parse_line(
            "Mar 10 08:15:22 web01 CRON[2400]: pam_unix(cron:session): session opened for user root",
            YEAR,
        )
        is None
    )
    assert (
        parse_line(
            "Mar 10 06:55:20 web01 sshd[2107]: Received disconnect from 203.0.113.7 port 40007:11: Bye Bye [preauth]",
            YEAR,
        )
        is None
    )
    assert parse_line("garbage line", YEAR) is None
    assert parse_line("", YEAR) is None


def test_parse_lines_yields_only_recognised_events():
    lines = [
        "Mar 10 06:55:05 web01 sshd[2102]: Failed password for root from 203.0.113.7 port 40003 ssh2",
        "garbage",
        "Mar 10 08:15:22 web01 CRON[2400]: session opened",
    ]
    events = list(parse_lines(lines, YEAR))
    assert len(events) == 1
    assert events[0].user == "root"
