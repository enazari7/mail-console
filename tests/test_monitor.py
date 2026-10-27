import os

from mailconsole import monitor


def fake_command(tmp_path, name, stdout, code=0):
    log = tmp_path / f"{name}.argv"
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\necho \"$@\" >> {log}\ncat <<'EOF'\n{stdout}\nEOF\nexit {code}\n")
    script.chmod(0o755)
    return str(script), log


def test_unit_status_parsing(tmp_path):
    out = ("Id=postfix@-.service\nLoadState=loaded\nActiveState=active\nSubState=running\n"
           "ActiveEnterTimestamp=Mon 2026-10-26 08:00:00 UTC\nMainPID=1203\nNRestarts=0\nResult=success")
    cmd, log = fake_command(tmp_path, "systemctl", out)
    s = monitor.check_unit(cmd, "Postfix", "postfix@-.service")
    assert s.ok and s.main_pid == 1203 and s.sub_state == "running"
    argv = log.read_text().split()
    assert argv[0] == "show" and argv[-1] == "postfix@-.service"  # read-only verb only


def test_missing_and_failed_units(tmp_path):
    cmd, _ = fake_command(tmp_path, "systemctl", "LoadState=not-found\nActiveState=inactive\nSubState=dead")
    s = monitor.check_unit(cmd, "Mailguard", "mailguard.service")
    assert not s.ok and "not found" in s.error
    s = monitor.check_unit("/nonexistent/systemctl", "X", "x.service")
    assert not s.ok and "unavailable" in s.error


def test_postqueue_json(tmp_path):
    out = ('{"queue_name": "deferred", "queue_id": "A1", "arrival_time": 100, "message_size": 5, "sender": "a@x", '
           '"recipients": [{"address": "b@y", "delay_reason": "timeout"}]}\n'
           '{"queue_name": "active", "queue_id": "A2", "arrival_time": 50, "message_size": 5, "sender": "", '
           '"recipients": [{"address": "c@y"}]}')
    cmd, log = fake_command(tmp_path, "postqueue", out)
    snap = monitor.check_queue(cmd)
    assert snap.ok and snap.total == 2 and snap.by_queue == {"deferred": 1, "active": 1}
    assert snap.oldest_arrival_ts == 50_000_000 and snap.entries[0]["queue_id"] == "A2"
    assert log.read_text().split() == ["-j"]  # never -f / -s / -i


def test_postqueue_failure_is_reported_not_faked(tmp_path):
    cmd, _ = fake_command(tmp_path, "postqueue", "", code=69)
    snap = monitor.check_queue(cmd)
    assert not snap.ok and snap.total is None
    assert os.path.exists(cmd)
