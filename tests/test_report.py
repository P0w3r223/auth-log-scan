import json
from datetime import datetime, timedelta

from auth_log_scan.analyze import analyze
from auth_log_scan.parse import AuthEvent, EventType
from auth_log_scan.report import render_terminal, to_json_dict

BASE = datetime(2026, 3, 10, 7, 0, 0)


def _sample_result():
    events = [
        AuthEvent(BASE + timedelta(seconds=2 * i), EventType.FAILED, "deploy", "198.51.100.23", port=1000 + i)
        for i in range(6)
    ]
    events.append(AuthEvent(BASE + timedelta(seconds=12), EventType.ACCEPTED, "deploy", "198.51.100.23", port=2000))
    return analyze(events, threshold=5, window=timedelta(seconds=60), min_success_failures=5)


def test_to_json_dict_is_serialisable_and_structured():
    result = _sample_result()
    payload = to_json_dict(result)
    text = json.dumps(payload)  # must not raise
    assert payload["summary"]["failed"] == 6
    assert payload["summary"]["accepted"] == 1
    assert len(payload["brute_force"]) == 1
    assert payload["brute_force"][0]["source_ip"] == "198.51.100.23"
    assert len(payload["suspicious_successes"]) == 1
    assert "198.51.100.23" in text


def test_render_terminal_contains_sections_and_flags():
    text = render_terminal(_sample_result())
    assert "auth-log-scan report" in text
    assert "brute-force sources (1)" in text
    assert "suspicious successes (1)" in text
    assert "198.51.100.23" in text


def test_render_terminal_handles_empty_result():
    text = render_terminal(analyze([]))
    assert "brute-force sources (0)" in text
    assert "none" in text
