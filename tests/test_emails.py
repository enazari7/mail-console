"""Emails page: search, filters, sorting, pagination, export, content, query plans."""

import csv
import io
import re

import pytest

from mailconsole import queries, web
from mailconsole.db import connect, migrate, tx

from .conftest import ingest_lines

# Pin the range so results do not depend on today's date.
FIXTURE_RANGE = {"range": "custom", "start": "2026-10-01T00:00", "end": "2026-11-01T00:00"}


def emails(client, **params):
    r = client.get("/emails", params={**FIXTURE_RANGE, **params})
    assert r.status_code == 200
    return r.text


def recipients_in(html: str) -> list[str]:
    return re.findall(r'class="to-link" href="/emails/\d+">([^<]+)</a>', html)


def row_keys(html: str) -> list[tuple[str, str]]:
    return re.findall(r'class="to-link" href="/emails/(\d+)">([^<]+)</a>', html)


def row_count(html: str) -> int:
    return html.count("<tr data-href=")


# --- search -------------------------------------------------------------------

@pytest.mark.parametrize("q,expected", [
    ("alice@example.org", {"alice@example.org"}),             # full recipient address
    ("ALICE@EXAMPLE.ORG", {"alice@example.org"}),             # case-insensitive
    ("lice@exa", {"alice@example.org"}),                       # partial
    ("3F2A61C0D3", {"alice@example.org"}),                     # Queue ID
    ("3f2a61", {"alice@example.org"}),                         # Queue ID prefix, any case
    ("<20261020090210.55aa@example.com>", {"bob@example.net", "nobody@example.org"}),  # Message-ID
    ("bounces@example.com", {"bob@example.net", "nobody@example.org", "bounces@example.com"}),  # sender + DSN rcpt
    ("example.invalid", {"grace@example.invalid", "victim@example.org"}),  # domain / sender domain
    ("Mailbox full", {"judy@example.com"}),                    # SMTP error text
    ("Spamhaus", {"frank@example.net"}),
    ("no-such-user@example.org", set()),
])
def test_search(logged_in, q, expected):
    assert set(recipients_in(emails(logged_in, q=q))) == expected


def test_search_shows_only_matching_recipient_rows(logged_in):
    # Message 4Xyz9… has three recipients; a recipient search shows just that row.
    assert recipients_in(emails(logged_in, q="judy@")) == ["judy@example.com"]
    # A message-wide match (Queue ID) shows every recipient of the message.
    assert len(recipients_in(emails(logged_in, q="4Xyz9Lmn7Qz3wJ"))) == 3


@pytest.mark.parametrize("q", ["%", "_", "%%%", "a_b", '"', '" OR "', "NEAR(a b)", "*", "a*", "'; DROP TABLE messages; --",
                               "\\"])
def test_search_escaping(logged_in, db, q):
    html = emails(logged_in, q=q)
    assert row_count(html) == 0 and "No emails found" in html
    assert db.execute("SELECT count(*) FROM messages").fetchone()[0] == 13


def test_wildcards_match_literally(logged_in, db, cfg):
    ingest_lines(db, cfg, [
        "2026-10-21T10:00:00+00:00 mail postfix/smtp[1]: ABCDEF0101: to=<odd_100%@example.org>, relay=mx[192.0.2.1]:25, "
        "delay=1, delays=0/0/1/0, dsn=2.0.0, status=sent (250 ok)",
        "2026-10-21T10:00:01+00:00 mail postfix/smtp[1]: ABCDEF0102: to=<oddx1000@example.org>, relay=mx[192.0.2.1]:25, "
        "delay=1, delays=0/0/1/0, dsn=2.0.0, status=sent (250 ok)",
    ])
    assert recipients_in(emails(logged_in, q="d_100%")) == ["odd_100%@example.org"]


def test_short_terms_are_exact_only(logged_in):
    html = emails(logged_in, q="ab")
    assert row_count(html) == 0 and "shorter than 3 characters" in html


def test_subject_is_searchable_when_logged(logged_in, db, cfg):
    ingest_lines(db, cfg, [
        "2026-10-22T09:00:00+00:00 mail postfix/smtpd[1]: ABCDEF0200: client=a[192.0.2.1]",
        "2026-10-22T09:00:00.1+00:00 mail postfix/cleanup[2]: ABCDEF0200: info: header Subject: Invoice 2026-10 ready "
        "from a[192.0.2.1]; from=<billing@example.com> to=<kim@example.org> proto=ESMTP helo=<a>",
        "2026-10-22T09:00:01+00:00 mail postfix/smtp[3]: ABCDEF0200: to=<kim@example.org>, relay=mx[192.0.2.9]:25, "
        "delay=1, delays=0/0/1/0, dsn=2.0.0, status=sent (250 ok)",
    ])
    html = emails(logged_in, q="invoice 2026")
    assert recipients_in(html) == ["kim@example.org"] and "Invoice 2026-10 ready" in html


# --- filters ------------------------------------------------------------------

def test_status_filters_are_per_recipient(logged_in):
    assert set(recipients_in(emails(logged_in, status="deferred"))) == {"ivan@example.net"}
    assert set(recipients_in(emails(logged_in, status="bounced"))) == {"nobody@example.org", "frank@example.net",
                                                                       "judy@example.com"}
    assert set(recipients_in(emails(logged_in, status="rejected"))) == {"victim@example.org", "dave@example.org"}
    assert set(recipients_in(emails(logged_in, status="expired"))) == {"grace@example.invalid"}
    # "Partially failed" is a message status: both recipients of the partial message are listed.
    assert set(recipients_in(emails(logged_in, status="partial"))) == {"bob@example.net", "nobody@example.org"}
    accepted = recipients_in(emails(logged_in, status="accepted"))
    assert "bob@example.net" in accepted and "nobody@example.org" not in accepted
    assert "Accepted by destination" in emails(logged_in, status="accepted")


def test_combined_filters_use_and(logged_in):
    html = emails(logged_in, status="bounced", sender="notify@example.com", q="mailbox")
    assert recipients_in(html) == ["judy@example.com"]
    # The sender matches "example.com", so every bounced recipient of that sender is listed.
    assert set(recipients_in(emails(logged_in, status="bounced", sender="notify@example.com", q="example.com"))) == {
        "judy@example.com", "frank@example.net"}
    assert recipients_in(emails(logged_in, status="bounced", domain="example.net")) == ["frank@example.net"]
    assert recipients_in(emails(logged_in, status="accepted", sender="bounces@example.com")) == ["bob@example.net"]


def test_sender_selector(logged_in):
    html = emails(logged_in)
    options = re.findall(r'class="dd-sender">([^<]+)</span>', html)
    assert options[0] == "notify@example.com"  # most frequent first
    assert {"bounces@example.com", "www-data@mail.example.com"} <= set(options)
    null_sender = recipients_in(emails(logged_in, sender="<>"))
    assert null_sender == ["bounces@example.com"]  # the Postfix-generated DSN
    # The selection stays visible.
    assert "Sender: www-data@mail.example.com" in emails(logged_in, sender="www-data@mail.example.com")


def test_custom_range_and_timezone(logged_in, db):
    from mailconsole.db import set_setting
    with tx(db):
        set_setting(db, "display_timezone", "Asia/Tehran")  # UTC+03:30
    # 3F2A61C0D3 was received at 08:15:01Z = 11:45:01 in Tehran.
    inside = emails(logged_in, range="custom", start="2026-10-20T11:45", end="2026-10-20T11:46")
    assert recipients_in(inside) == ["alice@example.org"]
    assert recipients_in(emails(logged_in, range="custom", start="2026-10-20T08:15", end="2026-10-20T08:16")) == []
    late = recipients_in(emails(logged_in, range="custom", start="2026-10-26T12:00", end="2026-10-27T00:00"))
    assert sorted(late) == ["heidi@example.org", "ivan@example.net", "judy@example.com"]


def test_presets_and_filters_survive_navigation(logged_in):
    html = emails(logged_in, status="bounced", q="example")
    # Every pagination/sort/dropdown link keeps the other filters.
    for href in re.findall(r'href="(/emails\?[^"]+)"', html):
        if "status=" not in href:
            continue
        assert "q=example" in href or "q=" not in href
    assert 'value="example"' in html  # search box keeps its value
    assert "Status: Bounced" in html


# --- sorting & pagination -----------------------------------------------------

@pytest.fixture
def many(db, cfg):
    lines = [f"2026-10-22T10:{i // 60:02d}:{i % 60:02d}+00:00 mail postfix/smtp[9]: {0xB00000 + i:08X}: "
             f"to=<p{i:03d}@bulk.example.org>, relay=mx[192.0.2.1]:25, delay=1, delays=0/0/1/0, dsn=2.0.0, "
             f"status=sent (250 ok)" for i in range(120)]
    ingest_lines(db, cfg, lines)


def test_pagination_boundaries(logged_in, many):
    first = emails(logged_in, domain="bulk.example.org")
    assert "1–50 of 120 emails" in first and "Page 1 of 3" in first and 'rel="next"' in first
    last = emails(logged_in, domain="bulk.example.org", page=3)
    assert row_count(last) == 20 and "101–120 of 120" in last and 'rel="next"' not in last
    assert "Page 3 of 3" in emails(logged_in, domain="bulk.example.org", page=999)
    assert "Page 1 of 3" in emails(logged_in, domain="bulk.example.org", page=-5)
    seen = []
    for page in (1, 2, 3):
        seen += recipients_in(emails(logged_in, domain="bulk.example.org", page=page))
    assert len(seen) == len(set(seen)) == 120  # no duplicates or gaps across pages


@pytest.mark.parametrize("sort", ["sent", "recipient", "status"])
@pytest.mark.parametrize("direction", ["asc", "desc"])
def test_sorting_is_stable(logged_in, many, sort, direction):
    def walk():
        keys = []
        for page in (1, 2, 3):  # 16 fixture rows + 120 generated rows, 50 per page
            keys += row_keys(emails(logged_in, sort=sort, dir=direction, page=page))
        return keys
    first = walk()
    assert len(first) == 136 and len(set(first)) == 136  # total order: no repeats or gaps across pages
    assert walk() == first  # deterministic


def test_sort_orders(logged_in, many):
    asc = recipients_in(emails(logged_in, domain="bulk.example.org", sort="recipient", dir="asc"))
    assert asc[:3] == ["p000@bulk.example.org", "p001@bulk.example.org", "p002@bulk.example.org"]
    newest = recipients_in(emails(logged_in, domain="bulk.example.org"))
    assert newest[0] == "p119@bulk.example.org"
    oldest = recipients_in(emails(logged_in, domain="bulk.example.org", dir="asc"))
    assert oldest[0] == "p000@bulk.example.org"


# --- rendering ------------------------------------------------------------------

def test_table_shows_status_subject_and_actions(logged_in):
    html = emails(logged_in, q="3F2A61C0D3")
    assert 'class="badge st-accepted"' in html and "Accepted by destination" in html
    assert "Not recorded" in html  # subject unknown, never fabricated
    assert 'data-copy="3F2A61C0D3"' in html and 'data-copy="&lt;20261020081501.1a2b3c@example.com&gt;"' in html
    assert re.search(r'<time datetime="2026-10-20T08:15:01\+00:00" title="2026-10-20 08:15:01 UTC">', html)
    assert "Receiving" in html and "not tracked" in html


def test_empty_state(logged_in):
    html = emails(logged_in, q="nothing-matches-this")
    assert "No emails found" in html and "Clear filters" in html and row_count(html) == 0
    quiet = logged_in.get("/emails", params={"range": "custom", "start": "2020-01-01T00:00",
                                             "end": "2020-01-02T00:00"}).text
    assert "has not logged any email" in quiet


def test_details_sections_and_content_placeholder(logged_in, db):
    mid = db.execute("SELECT id FROM messages WHERE queue_id = '7D1E80B2A4'").fetchone()[0]
    page = logged_in.get(f"/emails/{mid}").text
    for heading in ("Metadata", "Delivery events", "Message content", "Timeline"):
        assert f">{heading}<" in page
    assert "No archived copy." in page and "Subject not recorded" in page
    assert "Deferred attempts" in page and "Final event" in page and "mx.example.org[203.0.113.25]:25" in page
    assert "<iframe" not in page


# --- CSV export -----------------------------------------------------------------

def read_csv(resp):
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/csv")
    text = resp.content.decode("utf-8")
    assert text.startswith("﻿")
    return list(csv.reader(io.StringIO(text[1:])))


def test_export_respects_filters(logged_in):
    rows = read_csv(logged_in.get("/emails/export.csv", params={**FIXTURE_RANGE, "status": "bounced"}))
    header, body = rows[0], rows[1:]
    assert header[:4] == ["sent_at_utc", "sent_at_UTC", "recipient", "status"]
    assert {r[2] for r in body} == {"nobody@example.org", "frank@example.net", "judy@example.com"}
    assert all(r[3] == "Bounced" for r in body)
    assert "sasl" not in ",".join(header).lower() and "client" not in ",".join(header).lower()


def test_export_neutralises_formulas(logged_in, db, cfg):
    ingest_lines(db, cfg, [
        "2026-10-21T10:00:00+00:00 mail postfix/smtp[1]: ABCDEF0300: to=<=cmd|calc@example.org>, relay=mx[192.0.2.1]:25, "
        "delay=1, delays=0/0/1/0, dsn=5.0.0, status=bounced (=HYPERLINK(\"http://evil.example\") +1 @SUM)",
    ])
    rows = read_csv(logged_in.get("/emails/export.csv", params={**FIXTURE_RANGE, "q": "cmd|calc"}))
    [row] = rows[1:]
    assert row[2] == "'=cmd|calc@example.org" and row[8].startswith("'=HYPERLINK")
    assert web.csv_cell("@x") == "'@x" and web.csv_cell("-1") == "'-1" and web.csv_cell("plain") == "plain"


def test_export_is_bounded(logged_in, many, monkeypatch):
    monkeypatch.setattr(web, "EXPORT_MAX_ROWS", 25)
    resp = logged_in.get("/emails/export.csv", params={**FIXTURE_RANGE, "domain": "bulk.example.org"})
    assert len(read_csv(resp)) == 26 and resp.headers["x-export-truncated"] == "true"


def test_export_requires_login(client, admin):
    r = client.get("/emails/export.csv")
    assert r.status_code == 303 and "example" not in r.text


# --- performance: indexes and query plans -------------------------------------

def plan(conn, f: queries.ActivityFilter) -> str:
    where, args = queries._activity_where(f)
    sql = f"SELECT {queries.ROW_COLUMNS}{queries.BASE_FROM}{where} ORDER BY {queries._order(f)} LIMIT 50"
    return " | ".join(r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + sql, args))


def test_query_plans_use_indexes(db, cfg):
    from tests.conftest import fixture_lines
    ingest_lines(db, cfg, fixture_lines())
    db.execute("ANALYZE")
    default = plan(db, queries.ActivityFilter(start=0, end=2**62))
    assert "USING INDEX ix_messages_first_ts" in default or "USING INDEX ix_messages_first_ts_sender" in default
    assert "SCAN m " not in default + " "
    searched = plan(db, queries.ActivityFilter(q="alice@example", start=0, end=2**62))
    assert "VIRTUAL TABLE INDEX" in searched and "M1" in searched  # FTS5 MATCH, not a scan
    short = plan(db, queries.ActivityFilter(q="ab", start=0, end=2**62))
    assert "SCAN message_search" not in short
    sender = plan(db, queries.ActivityFilter(sender="notify@example.com", start=0, end=2**62))
    assert "INDEX" in sender
    recipients_join = default + searched
    assert "SCAN r" not in recipients_join  # recipients are always reached through an index


def test_upgrade_from_phase1_schema_builds_search_and_archive_tables(cfg, tmp_path):
    from mailconsole import db as dbmod
    from mailconsole import search
    conn = connect(tmp_path / "phase1.sqlite3")
    real = dbmod.available_migrations
    dbmod.available_migrations = lambda: [m for m in real() if m[0] == 1]
    try:
        migrate(conn)
    finally:
        dbmod.available_migrations = real
    # Rows exactly as the Phase 1 code wrote them (v1 schema).
    conn.executescript("""
        INSERT INTO messages(id, queue_id, host, first_ts, last_ts, sender, message_id, status, origin, nrcpt)
        VALUES (1, 'ABCDEF0900', 'mail', 1, 2, 'notify@example.com', 'v1@example.com', 'accepted', 'smtpd', 1);
        INSERT INTO recipients(message_id, address, domain, status, attempts)
        VALUES (1, 'alice@example.org', 'example.org', 'accepted', 1);
        INSERT INTO events(message_id, ts, program, queue_id, kind, recipient, status, line_hash)
        VALUES (1, 2, 'postfix/smtp', 'ABCDEF0900', 'delivery', 'alice@example.org', 'sent', x'01');
    """)
    applied = migrate(conn)
    assert applied == ["0002_search_and_content.sql", "0003_mail_content.sql"]
    assert search.missing_documents(conn) == 0
    assert conn.execute("SELECT count(*) FROM message_search WHERE message_search MATCH ?",
                        (search.phrase("alice@exa"),)).fetchone()[0] == 1
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert {"archives", "archive_parts", "archive_blobs", "archive_search", "audit_log", "pending_logins"} <= tables
    assert "message_content" not in tables
    assert conn.execute("SELECT archive_status FROM messages WHERE id = 1").fetchone()[0] is None

def test_search_index_follows_retention_and_resegmentation(db, cfg):
    from mailconsole import search
    from tests.conftest import fixture_lines
    ingest_lines(db, cfg, fixture_lines())
    assert search.missing_documents(db) == 0
    assert db.execute("SELECT count(*) FROM message_search").fetchone()[0] == 13
    with tx(db):
        db.execute("DELETE FROM messages WHERE queue_id = '3F2A61C0D3'")
    assert db.execute("SELECT count(*) FROM message_search WHERE message_search MATCH ?",
                      (search.phrase("3F2A61C0D3"),)).fetchone()[0] == 0


def test_correlation_lookup_by_queue_id_is_indexed(db):
    detail = " ".join(r[3] for r in db.execute(
        "EXPLAIN QUERY PLAN SELECT id, ts, kind, message_id FROM events WHERE queue_id = ? AND host IS ?",
        ("ABCDEF1234", "mail")))
    assert "USING INDEX ix_events_qid" in detail


# --- integration-review regressions ------------------------------------------

def test_migrate_completes_an_interrupted_index_build(cfg):
    from mailconsole import search
    from tests.conftest import fixture_lines
    conn = connect(cfg.db_path)
    migrate(conn)
    ingest_lines(conn, cfg, fixture_lines())
    conn.execute("DELETE FROM message_search WHERE rowid % 2 = 0")  # rebuild interrupted half-way
    assert search.missing_documents(conn) > 0
    assert migrate(conn) == []  # nothing pending, but the index is completed
    assert search.missing_documents(conn) == 0


def test_collector_resyncs_index_after_an_older_collector_ran(cfg):
    from mailconsole import search
    from mailconsole.collector import sync_search_index
    from mailconsole.db import set_state
    from tests.conftest import fixture_lines
    conn = connect(cfg.db_path)
    migrate(conn)
    ingest_lines(conn, cfg, fixture_lines())
    # Simulate a Phase 1 collector: it records its start and changes data
    # without touching the search index.
    with tx(conn):
        set_state(conn, "collector_started_ts", "1")
        conn.execute("UPDATE message_search SET doc = 'stale'")
        conn.execute("DELETE FROM message_search WHERE rowid = (SELECT max(id) FROM messages)")
    sync_search_index(conn)
    stale = [mid for mid, doc in conn.execute("SELECT rowid, doc FROM message_search")
             if doc != search.build_doc(conn, mid)]
    assert stale == [] and search.missing_documents(conn) == 0
    # A start recorded by the current collector does not trigger another rebuild.
    with tx(conn):
        set_state(conn, "collector_started_ts", "2")
        set_state(conn, "search_synced_start", "2")
        conn.execute("UPDATE message_search SET doc = 'kept' WHERE rowid = 1")
    sync_search_index(conn)
    assert conn.execute("SELECT doc FROM message_search WHERE rowid = 1").fetchone()[0] == "kept"


def test_nul_and_bracket_only_queries(logged_in):
    assert emails(logged_in, q="abc\x00def") and "No emails found" in emails(logged_in, q="abc\x00def")
    assert logged_in.get("/emails/export.csv", params={"q": "abc\x00def"}).status_code == 200
    html = emails(logged_in, q="<>")
    assert "Search:" not in html and row_count(html) > 0


def test_unicode_case_insensitive_search(logged_in, db, cfg):
    ingest_lines(db, cfg, [
        "2026-10-22T09:00:00+00:00 mail postfix/smtpd[1]: ABCDEF0400: client=a[192.0.2.1]",
        "2026-10-22T09:00:00.1+00:00 mail postfix/cleanup[2]: ABCDEF0400: info: header Subject: ÄRGER im Büro "
        "from a[192.0.2.1]; from=<b@example.com> to=<Ünal@example.org> proto=ESMTP helo=<a>",
        "2026-10-22T09:00:01+00:00 mail postfix/smtp[3]: ABCDEF0400: to=<Ünal@example.org>, relay=mx[192.0.2.9]:25, "
        "delay=1, delays=0/0/1/0, dsn=2.0.0, status=sent (250 ok)",
    ])
    for q in ("ÄRGER", "ärger", "ünal@", "ÜNAL"):
        assert recipients_in(emails(logged_in, q=q)) == ["Ünal@example.org"], q


def test_processing_filter_includes_partly_delivered_messages(logged_in, db, cfg):
    ingest_lines(db, cfg, [
        "2026-10-22T09:00:00+00:00 mail postfix/smtpd[1]: ABCDEF0500: client=a[192.0.2.1]",
        "2026-10-22T09:00:00.1+00:00 mail postfix/qmgr[2]: ABCDEF0500: from=<s@example.com>, size=1, nrcpt=2 (queue active)",
        "2026-10-22T09:00:01+00:00 mail postfix/smtp[3]: ABCDEF0500: to=<first@example.org>, relay=mx[192.0.2.9]:25, "
        "delay=1, delays=0/0/1/0, dsn=2.0.0, status=sent (250 ok)",
    ])
    assert "first@example.org" in recipients_in(emails(logged_in, status="processing"))


def test_overview_links_keep_the_range(logged_in):
    html = logged_in.get("/", params={"range": "90d"}).text
    assert "/emails?status=failed&amp;range=90d" in html
    assert re.search(r'/emails\?domain=example\.org&amp;range=90d', html)


def test_export_filename_marks_truncation(logged_in, many, monkeypatch):
    monkeypatch.setattr(web, "EXPORT_MAX_ROWS", 25)
    resp = logged_in.get("/emails/export.csv", params={**FIXTURE_RANGE, "domain": "bulk.example.org"})
    assert "-first-25-rows.csv" in resp.headers["content-disposition"]


