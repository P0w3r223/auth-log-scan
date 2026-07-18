from datetime import datetime, timedelta

from auth_log_scan.analyze import analyze
from auth_log_scan.parse import AuthEvent, EventType

BASE = datetime(2026, 3, 10, 7, 0, 0)


def failed(ip, offset, user="root", invalid=False):
    return AuthEvent(
        BASE + timedelta(seconds=offset), EventType.FAILED, user, ip, invalid_user=invalid, port=1000 + offset
    )


def accepted(ip, offset, user="deploy"):
    return AuthEvent(BASE + timedelta(seconds=offset), EventType.ACCEPTED, user, ip, port=1000 + offset)


def invalid(ip, offset, user):
    return AuthEvent(
        BASE + timedelta(seconds=offset), EventType.INVALID_USER, user, ip, invalid_user=True
    )


def test_brute_force_flagged_at_threshold_within_window():
    events = [failed("203.0.113.7", off) for off in (0, 2, 4, 6, 8)]
    result = analyze(events, threshold=5, window=timedelta(seconds=60))
    assert len(result.brute_force) == 1
    hit = result.brute_force[0]
    assert hit.source_ip == "203.0.113.7"
    assert hit.max_in_window == 5
    assert hit.failures == 5


def test_below_threshold_not_flagged():
    events = [failed("203.0.113.7", off) for off in (0, 2, 4, 6)]
    result = analyze(events, threshold=5, window=timedelta(seconds=60))
    assert result.brute_force == []


def test_failures_spread_beyond_window_not_flagged():
    # Five failures 20s apart: at most four fall inside any 60s window.
    events = [failed("203.0.113.7", off) for off in (0, 20, 40, 60, 80)]
    result = analyze(events, threshold=5, window=timedelta(seconds=60))
    assert result.brute_force == []


def test_suspicious_success_after_many_failures():
    events = [failed("198.51.100.23", off, user="deploy") for off in range(0, 12, 2)]  # 6 failures
    events.append(accepted("198.51.100.23", 12, user="deploy"))
    # Huge threshold + tiny window so brute-force does not fire; only the success detector should.
    result = analyze(events, threshold=100, window=timedelta(seconds=1), min_success_failures=5)
    assert result.brute_force == []
    assert len(result.suspicious_successes) == 1
    hit = result.suspicious_successes[0]
    assert hit.source_ip == "198.51.100.23"
    assert hit.prior_failures == 6


def test_success_with_few_prior_failures_not_suspicious():
    events = [failed("10.0.0.1", 0), failed("10.0.0.1", 2), accepted("10.0.0.1", 4, user="ok")]
    result = analyze(events, min_success_failures=5)
    assert result.suspicious_successes == []


def test_success_before_failures_is_not_suspicious():
    events = [accepted("10.0.0.9", 0, user="ok")] + [failed("10.0.0.9", off) for off in range(2, 14, 2)]
    result = analyze(events, min_success_failures=5)
    assert result.suspicious_successes == []


def test_enumeration_collects_invalid_users_and_counts_attempts():
    events = [
        invalid("203.0.113.7", 0, "admin"),
        failed("203.0.113.7", 0, user="admin", invalid=True),
        invalid("203.0.113.7", 2, "oracle"),
        failed("203.0.113.7", 2, user="oracle", invalid=True),
        failed("203.0.113.7", 4, user="root"),
        failed("203.0.113.7", 6, user="root"),
    ]
    result = analyze(events)
    assert result.invalid_usernames == ["admin", "oracle"]
    assert result.invalid_user_events == 2  # two "Invalid user" lines
    top = dict(result.top_targeted_users)  # counts FAILED events only
    assert top["root"] == 2
    assert top["admin"] == 1
    assert top["oracle"] == 1


def test_empty_events_gives_empty_result():
    result = analyze([])
    assert result.total_events == 0
    assert result.brute_force == []
    assert result.suspicious_successes == []
    assert result.first_seen is None


def test_summary_counts_and_time_range():
    events = [failed("1.1.1.1", 0), accepted("2.2.2.2", 10, user="ok"), invalid("1.1.1.1", 5, "x")]
    result = analyze(events)
    assert result.failed == 1
    assert result.accepted == 1
    assert result.invalid_user_events == 1
    assert result.first_seen == BASE
    assert result.last_seen == BASE + timedelta(seconds=10)


def test_top_source_ips_ordered_by_failures():
    events = [failed("1.1.1.1", i) for i in range(3)] + [failed("2.2.2.2", i + 20) for i in range(5)]
    result = analyze(events, threshold=100)  # avoid brute-force flags; only check ordering
    assert result.top_source_ips[0] == ("2.2.2.2", 5)
    assert result.top_source_ips[1] == ("1.1.1.1", 3)
