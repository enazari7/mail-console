import random

from mailconsole.correlate import recompute_message

from .conftest import fixture_lines, ingest_lines, snapshot


def by_qid(conn, qid):
    return [dict(r) for r in conn.execute("SELECT * FROM messages WHERE queue_id = ? ORDER BY first_ts", (qid,))]


def recipients(conn, message_id):
    return {r["address"]: dict(r) for r in conn.execute("SELECT * FROM recipients WHERE message_id = ?", (message_id,))}


def test_fixture_outcomes(db, cfg):
    ingest_lines(db, cfg, fixture_lines())
    statuses = {(r["queue_id"], r["first_ts"]): r["status"] for r in db.execute("SELECT * FROM messages")}
    assert len(statuses) == 13
    assert by_qid(db, "3F2A61C0D3")[0]["status"] == "accepted"
    assert by_qid(db, "F1E2D3C4B5")[0]["status"] == "rejected"
    assert by_qid(db, "C0FFEE1234")[0]["status"] == "expired"
    assert by_qid(db, "4Xyz9Lmn7Qz3wJ")[0]["status"] == "deferred"
    noqueue = db.execute("SELECT * FROM messages WHERE queue_id IS NULL").fetchall()
    assert len(noqueue) == 1 and noqueue[0]["status"] == "rejected" and noqueue[0]["origin"] == "noqueue"


def test_queue_id_groups_full_lifecycle(db, cfg):
    ingest_lines(db, cfg, fixture_lines())
    [m] = by_qid(db, "3F2A61C0D3")
    assert m["sender"] == "notify@example.com"
    assert m["message_id"] == "20261020081501.1a2b3c@example.com"
    assert m["sasl_username"] == "notify@example.com" and m["client"] == "app.example.net[198.51.100.20]"
    assert m["size"] == 4821 and m["nrcpt"] == 1 and m["origin"] == "smtpd"
    assert m["has_start"] and m["has_qmgr"] and m["closed_ts"]
    kinds = [r[0] for r in db.execute("SELECT kind FROM events WHERE message_id = ? ORDER BY ts", (m["id"],))]
    assert kinds == ["connect", "cleanup", "milter_info", "queued", "delivery", "removed"]
    r = recipients(db, m["id"])["alice@example.org"]
    assert r["status"] == "accepted" and r["dsn"] == "2.0.0" and r["delay"] == 1.3
    assert r["relay"] == "mx.example.org[203.0.113.25]:25" and "gsmtp" in r["response"]


def test_multiple_recipients_and_dsn_child(db, cfg):
    ingest_lines(db, cfg, fixture_lines())
    [m] = by_qid(db, "7D1E80B2A4")
    rc = recipients(db, m["id"])
    assert rc["bob@example.net"]["status"] == "accepted"
    assert rc["nobody@example.org"]["status"] == "bounced" and rc["nobody@example.org"]["dsn"] == "5.1.1"
    assert m["status"] == "partial" and m["notification_qid"] == "9C4F10B2B7"
    [child] = by_qid(db, "9C4F10B2B7")
    assert child["origin"] == "dsn" and child["sender"] == "" and child["status"] == "accepted"
    # Three recipients: accepted, deferred, bounced -> still deferred overall.
    [multi] = by_qid(db, "4Xyz9Lmn7Qz3wJ")
    assert {a: r["status"] for a, r in recipients(db, multi["id"]).items()} == {
        "heidi@example.org": "accepted", "ivan@example.net": "deferred", "judy@example.com": "bounced"}
    assert multi["status"] == "deferred"


def test_retries_deferrals_then_accepted(db, cfg):
    ingest_lines(db, cfg, fixture_lines())
    [m] = by_qid(db, "A3B5C7D9E1")
    r = recipients(db, m["id"])["carol@example.net"]
    assert (r["attempts"], r["deferrals"], r["status"], r["dsn"]) == (3, 2, "accepted", "2.0.0")
    assert m["active_count"] == 3 and m["status"] == "accepted"


def test_expiry_marks_deferred_recipient_expired(db, cfg):
    ingest_lines(db, cfg, fixture_lines())
    [m] = by_qid(db, "C0FFEE1234")
    r = recipients(db, m["id"])["grace@example.invalid"]
    assert r["status"] == "expired" and r["deferrals"] == 2 and r["final_ts"] is not None
    assert m["notification_qid"] == "1D2E3F4A5B"


def test_queue_id_reuse_creates_separate_messages(db, cfg):
    ingest_lines(db, cfg, fixture_lines())
    first, second = by_qid(db, "2B4C6D8E0F")
    assert first["message_id"] == "first-use@example.com" and first["status"] == "accepted"
    assert second["message_id"] == "second-use@example.com" and second["status"] == "bounced"
    assert set(recipients(db, first["id"])) == {"erin@example.org"}
    assert set(recipients(db, second["id"])) == {"frank@example.net"}


def test_reuse_without_removed_line_split_on_second_start(db, cfg):
    lines = [
        "2026-10-20T12:00:00.000000+00:00 mail postfix/smtpd[1]: ABCDEF0001: client=a[192.0.2.1]",
        "2026-10-20T12:00:00.100000+00:00 mail postfix/qmgr[2]: ABCDEF0001: from=<a@example.com>, size=1, nrcpt=1 (queue active)",
        # The 'removed' line is missing (log gap); the ID is then reused.
        "2026-10-20T13:00:00.000000+00:00 mail postfix/smtpd[3]: ABCDEF0001: client=b[192.0.2.2]",
        "2026-10-20T13:00:00.100000+00:00 mail postfix/qmgr[2]: ABCDEF0001: from=<b@example.com>, size=1, nrcpt=1 (queue active)",
    ]
    ingest_lines(db, cfg, lines)
    first, second = by_qid(db, "ABCDEF0001")
    assert (first["sender"], second["sender"]) == ("a@example.com", "b@example.com")
    assert first["closed_ts"] is None and first["status"] == "processing"


def test_long_silence_splits_messages_without_start(db, cfg):
    lines = [
        "2026-10-01T12:00:00+00:00 mail postfix/qmgr[2]: ABCDEF0002: from=<a@example.com>, size=1, nrcpt=1 (queue active)",
        "2026-10-20T12:00:00+00:00 mail postfix/qmgr[2]: ABCDEF0002: from=<b@example.com>, size=1, nrcpt=1 (queue active)",
    ]
    ingest_lines(db, cfg, lines)
    assert len(by_qid(db, "ABCDEF0002")) == 2


def test_incomplete_history_is_explicit(db, cfg):
    lines = ["2026-10-20T12:00:01+00:00 mail postfix/smtp[5]: ABCDEF0003: to=<x@example.org>, relay=none, "
             "delay=1, delays=0/0/1/0, dsn=4.4.1, status=deferred (connect to mx.example.org[192.0.2.9]:25: timeout)"]
    ingest_lines(db, cfg, lines)
    [m] = by_qid(db, "ABCDEF0003")
    assert m["sender"] is None and m["has_start"] == 0 and m["has_qmgr"] == 0
    assert m["origin"] == "unknown" and m["status"] == "deferred"


def test_milter_reject_and_noqueue(db, cfg):
    ingest_lines(db, cfg, fixture_lines())
    [m] = by_qid(db, "F1E2D3C4B5")
    r = recipients(db, m["id"])["dave@example.org"]
    assert r["status"] == "rejected" and r["dsn"] == "5.7.1" and m["sender"] == "ceo@example.com"


def test_duplicate_lines_are_idempotent(db, cfg):
    lines = fixture_lines()
    first = ingest_lines(db, cfg, lines)
    before = snapshot(db)
    events = db.execute("SELECT count(*) FROM events").fetchone()[0]
    second = ingest_lines(db, cfg, lines + lines[:10])
    assert second.events == 0 and second.ops == 0
    assert second.duplicates >= first.events + first.ops
    assert snapshot(db) == before
    assert db.execute("SELECT count(*) FROM events").fetchone()[0] == events


def test_out_of_order_ingestion_gives_same_result(db, cfg, tmp_path):
    lines = fixture_lines()
    ingest_lines(db, cfg, lines)
    expected = snapshot(db)

    from mailconsole.db import connect, migrate
    for name, order in (("split", lines[40:] + lines[:40]), ("reversed", list(reversed(lines))),
                        ("shuffled-batches", None)):
        conn = connect(tmp_path / f"{name}.sqlite3")
        migrate(conn)
        if order is None:
            chunks = [lines[i:i + 7] for i in range(0, len(lines), 7)]
            random.Random(7).shuffle(chunks)
            for chunk in chunks:
                ingest_lines(conn, cfg, chunk)
        else:
            ingest_lines(conn, cfg, order)
        assert snapshot(conn) == expected, name
        conn.close()


def test_event_cap_keeps_final_outcome(db, cfg):
    lines = ["2026-10-20T12:00:00+00:00 mail postfix/smtpd[1]: ABCDEF0004: client=a[192.0.2.1]"]
    for i in range(30):
        lines.append(f"2026-10-20T12:{i + 1:02d}:00+00:00 mail postfix/smtp[5]: ABCDEF0004: to=<x@example.org>, "
                     f"relay=none, delay={i}, delays=0/0/1/0, dsn=4.4.1, status=deferred (timeout {i})")
    lines.append("2026-10-20T13:00:00+00:00 mail postfix/smtp[5]: ABCDEF0004: to=<x@example.org>, relay=mx[192.0.2.9]:25, "
                 "delay=3600, delays=0/0/1/0, dsn=2.0.0, status=sent (250 ok)")
    stats = ingest_lines(db, cfg, lines, max_events=10)
    [m] = by_qid(db, "ABCDEF0004")
    assert stats.dropped == 21 and m["events_truncated"] == 1
    assert m["status"] == "accepted"


def test_recompute_is_stable(db, cfg):
    ingest_lines(db, cfg, fixture_lines())
    before = snapshot(db)
    for (mid,) in db.execute("SELECT id FROM messages").fetchall():
        recompute_message(db, mid)
    assert snapshot(db) == before
