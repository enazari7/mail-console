import gzip
import json
import os
import stat
from datetime import datetime, timezone

import pytest

from mailconsole.collector import (
    Collector, CollectorLock, LockBusy, apply_retention, import_files,
)
from mailconsole.db import connect, now_us, set_setting, tx
from mailconsole.sources import FileSource, JournaldSource, load_checkpoint, rotated_siblings

from .conftest import ISO_LOG, fixture_lines, ingest_lines, snapshot


def drain(collector, conn, limit=50):
    from mailconsole.collector import make_ingestor
    ingestor = make_ingestor(conn, collector.cfg)
    for _ in range(limit):
        if not collector.step(conn, ingestor):
            # One more step lets a rotation finish once the old file is drained.
            if not collector.step(conn, ingestor):
                return
    raise AssertionError("collector did not settle")


def write(path, lines, mode="a"):
    with open(path, mode) as fh:
        fh.write("".join(line + "\n" for line in lines))


def reference_snapshot(cfg, tmp_path):
    conn = connect(tmp_path / "reference.sqlite3")
    from mailconsole.db import migrate
    migrate(conn)
    ingest_lines(conn, cfg, fixture_lines())
    snap = snapshot(conn)
    conn.close()
    return snap


def test_incremental_tailing_and_partial_lines(db, cfg, tmp_path):
    lines = fixture_lines()
    log = cfg.log_path
    write(log, lines[:30], "w")
    collector = Collector(cfg, enable_monitor=False)
    drain(collector, db)
    with open(log, "a") as fh:
        fh.write(lines[30] + "\n" + lines[31][:25])  # incomplete trailing line
    drain(collector, db)
    cp = load_checkpoint(db, collector.source.name)
    assert cp.offset == sum(len(x) + 1 for x in lines[:31])
    with open(log, "a") as fh:
        fh.write(lines[31][25:] + "\n")
    write(log, lines[32:])
    drain(collector, db)
    assert snapshot(db) == reference_snapshot(cfg, tmp_path)


def test_restart_resumes_from_checkpoint_without_duplicates(db, cfg, tmp_path):
    lines = fixture_lines()
    write(cfg.log_path, lines[:40], "w")
    drain(Collector(cfg, enable_monitor=False), db)
    db.close()
    conn = connect(cfg.db_path)  # simulated service restart
    write(cfg.log_path, lines[40:])
    drain(Collector(cfg, enable_monitor=False), conn)
    assert snapshot(conn) == reference_snapshot(cfg, tmp_path)
    dupes = conn.execute("SELECT value FROM collector_state WHERE key = 'duplicates_total'").fetchone()
    assert dupes is None or dupes[0] == "0"
    conn.close()


def test_rotation_rename_create_with_late_writes(db, cfg, tmp_path):
    lines = fixture_lines()
    log = cfg.log_path
    write(log, lines[:20], "w")
    collector = Collector(cfg, enable_monitor=False)
    drain(collector, db)
    write(log, lines[20:30])                 # written but not yet read
    os.rename(log, str(log) + ".1")          # logrotate (delaycompress)
    write(str(log) + ".1", lines[30:35])     # rsyslog writes to the old fd until HUP
    write(log, lines[35:], "w")              # new file after HUP
    drain(collector, db)
    assert snapshot(db) == reference_snapshot(cfg, tmp_path)
    notes = [r[0] for r in db.execute("SELECT message FROM ops_events WHERE program = 'mail-console'")]
    assert any("finished rotated file" in n for n in notes)


def test_rotation_with_immediate_compression(db, cfg, tmp_path):
    lines = fixture_lines()
    log = cfg.log_path
    write(log, lines[:20], "w")
    collector = Collector(cfg, enable_monitor=False)
    drain(collector, db)
    write(log, lines[20:40])
    with open(log, "rb") as src, gzip.open(str(log) + ".1.gz", "wb") as dst:
        dst.write(src.read())
    os.unlink(log)
    write(log, lines[40:], "w")
    drain(collector, db)
    assert snapshot(db) == reference_snapshot(cfg, tmp_path)


def test_copytruncate_reads_the_copy_then_the_truncated_file(db, cfg, tmp_path):
    lines = fixture_lines()
    log = cfg.log_path
    write(log, lines[:20], "w")
    collector = Collector(cfg, enable_monitor=False)
    drain(collector, db)
    write(log, lines[20:30])
    with open(log, "rb") as src, open(str(log) + ".1", "wb") as dst:   # logrotate copytruncate
        dst.write(src.read())
    os.truncate(log, 0)
    write(log, lines[30:])
    drain(collector, db)
    assert snapshot(db) == reference_snapshot(cfg, tmp_path)


def test_unrecoverable_replacement_is_reported(db, cfg):
    lines = fixture_lines()
    log = cfg.log_path
    write(log, lines[:20], "w")
    collector = Collector(cfg, enable_monitor=False)
    drain(collector, db)
    write(log, lines[20:22], "w")   # rewritten in place, no copy kept
    drain(collector, db)
    os.unlink(log)                   # replaced, old file gone
    write(log, lines[22:], "w")
    drain(collector, db)
    notes = " ".join(r[0] for r in db.execute("SELECT message FROM ops_events WHERE program = 'mail-console'"))
    assert "rewritten in place" in notes and "previous file was not found" in notes


def test_inode_reuse_detected_by_fingerprint(tmp_path):
    log = tmp_path / "syslog"
    write(log, ["2026-10-20T00:00:00+00:00 mail postfix/qmgr[1]: ABCDEF1234: removed"] * 3, "w")
    src = FileSource(log)
    batch = src.poll(None, 100)
    assert len(batch.lines) == 3
    cp = batch.checkpoint
    # Same inode, different content of greater length: treat as new file.
    write(log, ["2026-10-21T00:00:00+00:00 mail postfix/qmgr[1]: BBBBBB1234: removed"] * 5, "w")
    batch = src.poll(cp, 100)
    assert len(batch.lines) == 5


def test_overlong_lines_are_truncated_not_split(tmp_path):
    log = tmp_path / "syslog"
    with open(log, "w") as fh:
        fh.write("x" * 5000 + "\n" + "short\n")
    batch = FileSource(log, max_line_bytes=1024).poll(None, 100)
    assert [len(x) for x, _ in batch.lines] == [1024, 5]


def test_historical_import_rotated_files_is_idempotent(db, cfg, tmp_path):
    lines = fixture_lines()
    log = cfg.log_path
    with gzip.open(str(log) + ".2.gz", "wt") as fh:
        fh.write("\n".join(lines[:25]) + "\n")
    write(str(log) + ".1", lines[25:50], "w")
    write(log, lines[50:], "w")
    assert [p.name for p in rotated_siblings(log)] == ["syslog.2.gz", "syslog.1"]
    db.close()
    first = import_files(cfg, rotated_siblings(log) + [log], echo=lambda _: None)
    again = import_files(cfg, rotated_siblings(log) + [log], echo=lambda _: None)
    assert first.events > 0 and again.events == 0
    conn = connect(cfg.db_path)
    # The live collector then starts on the current file: everything is a duplicate.
    drain(Collector(cfg, enable_monitor=False), conn)
    assert snapshot(conn) == reference_snapshot(cfg, tmp_path)
    conn.close()


def test_import_refuses_while_collector_holds_lock(cfg, db):
    with CollectorLock(cfg.data_dir / "collector.lock"):
        with pytest.raises(LockBusy):
            import_files(cfg, [ISO_LOG], echo=lambda _: None)


def test_retention_and_size_cap(db, cfg):
    ingest_lines(db, cfg, fixture_lines())
    total = db.execute("SELECT count(*) FROM messages").fetchone()[0]
    with tx(db):
        set_setting(db, "retention_days", "7")
    now = int(datetime(2026, 10, 30, tzinfo=timezone.utc).timestamp()) * 1_000_000  # cutoff 2026-10-23
    result = apply_retention(db, cfg, now=now)
    remaining = db.execute("SELECT count(*) FROM messages").fetchone()[0]
    assert result["messages"] == total - remaining and remaining == 3  # only messages last seen on 2026-10-26 survive
    assert db.execute("SELECT count(*) FROM events WHERE message_id NOT IN (SELECT id FROM messages)").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM recipients WHERE message_id NOT IN (SELECT id FROM messages)").fetchone()[0] == 0


def test_size_cap_trims_oldest(db, cfg, monkeypatch):
    lines = []
    for i in range(400):
        qid = f"{0xA00000 + i:08X}"
        lines.append(f"2026-10-{1 + i // 20:02d}T12:{i % 60:02d}:00+00:00 mail postfix/smtp[5]: {qid}: to=<u{i}@example.org>, "
                     f"relay=mx[192.0.2.1]:25, delay=1, delays=0/0/1/0, dsn=2.0.0, status=sent (250 {'x' * 1500})")
    ingest_lines(db, cfg, lines)
    import dataclasses
    small = dataclasses.replace(cfg, max_db_mb=1)
    result = apply_retention(db, small, now=now_us())
    assert result["size_cap_trimmed"] > 0
    oldest = db.execute("SELECT min(first_ts) FROM messages").fetchone()[0]
    assert oldest > int(datetime(2026, 10, 2, tzinfo=timezone.utc).timestamp()) * 1_000_000  # oldest days went first


def test_database_files_are_private(db, cfg):
    mode = stat.S_IMODE(os.stat(cfg.db_path).st_mode)
    assert mode == 0o600


def test_journald_source_with_cursor(tmp_path):
    entries = [
        {"__CURSOR": f"c{i}", "__REALTIME_TIMESTAMP": str(1760948101000000 + i), "_HOSTNAME": "mail",
         "SYSLOG_IDENTIFIER": "postfix/qmgr", "SYSLOG_PID": "1203", "MESSAGE": f"ABCDEF{i:04d}: removed"}
        for i in range(5)
    ]
    data = tmp_path / "journal.json"
    data.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
    fake = tmp_path / "journalctl"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "cursor = next((a.split('=', 1)[1] for a in sys.argv if a.startswith('--after-cursor=')), None)\n"
        f"lines = open({str(data)!r}).read().splitlines()\n"
        "seen = cursor is None\n"
        "for line in lines:\n"
        "    if seen: print(line)\n"
        "    if json.loads(line)['__CURSOR'] == cursor: seen = True\n")
    fake.chmod(0o755)
    src = JournaldSource(str(fake), ["postfix@-.service"])
    batch = src.poll(None, 3)
    assert [r.message for r in batch.records] == ["ABCDEF0000: removed", "ABCDEF0001: removed", "ABCDEF0002: removed"]
    assert batch.more and batch.checkpoint.cursor == "c2"
    batch = src.poll(batch.checkpoint, 10)
    assert [r.message for r in batch.records] == ["ABCDEF0003: removed", "ABCDEF0004: removed"]
    assert batch.records[0].program == "postfix/qmgr" and batch.records[0].pid == 1203
    assert "--unit" in src.command(None)
