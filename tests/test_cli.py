import io
import json

from auth_log_scan.cli import main

SAMPLE = "\n".join(
    [
        "Mar 10 07:10:00 web01 sshd[1]: Failed password for deploy from 198.51.100.23 port 1 ssh2",
        "Mar 10 07:10:02 web01 sshd[2]: Failed password for deploy from 198.51.100.23 port 2 ssh2",
        "Mar 10 07:10:04 web01 sshd[3]: Failed password for deploy from 198.51.100.23 port 3 ssh2",
        "Mar 10 07:10:06 web01 sshd[4]: Failed password for deploy from 198.51.100.23 port 4 ssh2",
        "Mar 10 07:10:08 web01 sshd[5]: Failed password for deploy from 198.51.100.23 port 5 ssh2",
        "Mar 10 07:10:10 web01 sshd[6]: Accepted password for deploy from 198.51.100.23 port 6 ssh2",
    ]
)


def test_main_reads_file_and_prints_report(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text(SAMPLE + "\n", encoding="utf-8")
    rc = main([str(log), "--year", "2026"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "auth-log-scan report" in out
    assert "198.51.100.23" in out


def test_main_reads_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(SAMPLE))
    rc = main(["-", "--year", "2026"])
    assert rc == 0
    assert "198.51.100.23" in capsys.readouterr().out


def test_json_export_to_file(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(SAMPLE + "\n", encoding="utf-8")
    out_json = tmp_path / "out.json"
    rc = main([str(log), "--year", "2026", "--json", str(out_json)])
    assert rc == 0
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["summary"]["failed"] == 5
    assert data["summary"]["accepted"] == 1
    assert data["brute_force"][0]["source_ip"] == "198.51.100.23"


def test_json_to_stdout(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text(SAMPLE + "\n", encoding="utf-8")
    rc = main([str(log), "--year", "2026", "--json", "-"])
    assert rc == 0
    assert '"summary"' in capsys.readouterr().out


def test_missing_file_returns_error(capsys):
    rc = main(["/no/such/file.log", "--year", "2026"])
    assert rc == 1
    assert "cannot read" in capsys.readouterr().err
