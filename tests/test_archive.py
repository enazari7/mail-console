"""Message capture, archive storage, correlation, viewing and security."""

import dataclasses
import errno
import io
import json
import os
import re
import time
import tracemalloc
from email import policy
from email.message import EmailMessage

import pytest

from mailconsole import archive, blobstore, capture, mime
from mailconsole.collector import Collector

from .conftest import PASSWORD, ingest_lines, login

ARCHIVE_RCPT = "archive@mail-console.invalid"
PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 20


@pytest.fixture
def acfg(cfg, tmp_path):
    spool = tmp_path / "spool" / "incoming"
    spool.mkdir(parents=True)
    key = tmp_path / "archive.key"
    key.write_text(blobstore.new_key_hex())
    return dataclasses.replace(cfg, archive_spool=spool, archive_dir=tmp_path / "archive", archive_key_file=key,
                               archive_min_free_bytes=1)


@pytest.fixture
def store(acfg):
    return archive.open_store(acfg)


def make_message(msgid="<m1@example.com>", subject="Your verification code", attachments=True) -> bytes:
    m = EmailMessage()
    m["Subject"] = subject
    m["From"] = "BeastPing <notify@example.com>"
    m["To"] = "Ali <ali@example.org>"
    m["Cc"] = "team@example.net"
    if msgid:
        m["Message-ID"] = msgid
    m.set_content("کد تأیید شما 482913 است.\nReset: https://example.com/reset?token=Zz9")
    m.add_alternative('<html dir="rtl"><body><p>کد <b>482913</b></p><img src="cid:logo1">'
                      '<img src="https://tracker.example/p.gif"><script>alert(1)</script>'
                      '<meta http-equiv="refresh" content="0;url=https://evil.example/">'
                      '<a href="https://example.com/x">link</a></body></html>', subtype="html")
    m.get_payload()[1].add_related(PNG, maintype="image", subtype="png", cid="<logo1>")
    if attachments:
        m.add_attachment(b"%PDF-1.4 " + os.urandom(20000), maintype="application", subtype="pdf",
                         filename="فاکتور ۱۲.pdf")
        m.add_attachment(b"<script>alert('x')</script>", maintype="text", subtype="html", filename="evil.html")
    return m.as_bytes(policy=policy.SMTP).replace(b"\r\n", b"\n")   # pipe(8) delivers LF line endings


def spool_capture(acfg, data: bytes, qid: str, at_us: int, sender="notify@example.com") -> str:
    return capture.capture(io.BytesIO(data), str(acfg.archive_spool), qid, sender, "notify@example.com", 1,
                           now_us=at_us)


def log_lines(qid: str, t: str, msgid: str | None = "m1@example.com", archive_ok=True) -> list[str]:
    lines = [
        f"{t}.000000+00:00 mail postfix/submission/smtpd[1]: {qid}: client=app.example.net[198.51.100.20], "
        "sasl_method=PLAIN, sasl_username=notify@example.com",
        f"{t}.100000+00:00 mail postfix/qmgr[2]: {qid}: from=<notify@example.com>, size=3000, nrcpt=2 (queue active)",
        f"{t}.400000+00:00 mail postfix/smtp[3]: {qid}: to=<ali@example.org>, relay=mx.example.org[203.0.113.25]:25, "
        "delay=0.4, delays=0.1/0/0.1/0.2, dsn=2.0.0, status=sent (250 2.0.0 OK)",
        (f"{t}.300000+00:00 mail postfix/pipe[4]: {qid}: to=<{ARCHIVE_RCPT}>, relay=mailconsole-archive, "
         "delay=0.3, delays=0.1/0/0/0.2, dsn=2.0.0, status=sent (delivered via mailconsole-archive service)")
        if archive_ok else
        (f"{t}.300000+00:00 mail postfix/pipe[4]: {qid}: to=<{ARCHIVE_RCPT}>, relay=mailconsole-archive, "
         "delay=0.3, delays=0.1/0/0/0.2, dsn=4.3.0, status=deferred (temporary failure. Command output: "
         "mail-console capture deferred: archive spool is low on disk space)"),
    ]
    if msgid:
        lines.insert(1, f"{t}.050000+00:00 mail postfix/cleanup[5]: {qid}: message-id=<{msgid}>")
    if archive_ok:
        lines.append(f"{t}.500000+00:00 mail postfix/qmgr[2]: {qid}: removed")
    return lines


def us(iso: str) -> int:
    from datetime import datetime
    return int(datetime.fromisoformat(iso + "+00:00").timestamp() * 1_000_000)


def ingest_all(db, acfg, store):
    stats = archive.process_spool(db, acfg, store)
    archive.relink(db, stats.queue_ids)
    return stats


# --- capture (the Postfix pipe program) ---------------------------------------

def test_capture_is_atomic_and_exact(acfg):
    data = make_message()
    assert capture.main(["--queue-id=ABCDEF1001", "--sender=notify@example.com",
                         f"--spool={acfg.archive_spool}", "--min-free-mb=0"], stdin=io.BytesIO(data)) == 0
    files = sorted(os.listdir(acfg.archive_spool))
    assert len(files) == 2 and files[0].endswith(".eml") and files[1].endswith(".json")
    eml = (acfg.archive_spool / files[0]).read_bytes()
    meta = json.loads((acfg.archive_spool / files[1]).read_text())
    assert eml == data and meta["size"] == len(data) and meta["queue_id"] == "ABCDEF1001"
    import hashlib
    assert meta["sha256"] == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("args", [["--queue-id=../../etc"], ["--queue-id=ABCDEF1001", "--spool=/nonexistent/x"],
                                  ["--bogus"]])
def test_capture_defers_on_bad_input(acfg, args):
    if not any(a.startswith("--spool") for a in args):
        args = args + [f"--spool={acfg.archive_spool}"]
    assert capture.main(args, stdin=io.BytesIO(b"x")) == capture.EX_TEMPFAIL
    assert os.listdir(acfg.archive_spool) == []


def test_storage_pressure_skips_with_a_marker_instead_of_holding_mail(acfg, monkeypatch):
    msg = b"Subject: x\n\nbody\n"
    # Low disk: exit 0 so Postfix finishes the queue file; a marker records the skip.
    rc = capture.main(["--queue-id=ABCDEF1002", f"--spool={acfg.archive_spool}", "--min-free-mb=99999999"],
                      stdin=io.BytesIO(msg))
    names = os.listdir(acfg.archive_spool)
    assert rc == 0 and len(names) == 1 and names[0].endswith(".skipped.json")
    marker = json.loads((acfg.archive_spool / names[0]).read_text())
    assert marker["queue_id"] == "ABCDEF1002" and marker["size"] == len(msg) and "free disk" in marker["skipped"]
    (acfg.archive_spool / names[0]).unlink()
    # Spool over its cap (the console is not ingesting).
    (acfg.archive_spool / "100-ABCDEF0000-aaaaaaaa.eml").write_bytes(b"x" * 2 * 1024 * 1024)
    rc = capture.main(["--queue-id=ABCDEF1003", f"--spool={acfg.archive_spool}", "--min-free-mb=0",
                       "--max-spool-mb=1"], stdin=io.BytesIO(msg))
    assert rc == 0 and any(n.endswith(".skipped.json") for n in os.listdir(acfg.archive_spool))
    for n in os.listdir(acfg.archive_spool):
        (acfg.archive_spool / n).unlink()

    # ENOSPC while writing (even the marker cannot be written): still exit 0, no partial files.
    def enospc(fd, data):
        raise OSError(errno.ENOSPC, "No space left on device")
    monkeypatch.setattr(capture.os, "write", enospc)
    rc = capture.main(["--queue-id=ABCDEF1004", f"--spool={acfg.archive_spool}", "--min-free-mb=0"],
                      stdin=io.BytesIO(msg))
    assert rc == 0 and os.listdir(acfg.archive_spool) == []


def test_wrapper_maps_every_failure_to_tempfail():
    import subprocess
    from pathlib import Path
    wrapper = Path(__file__).resolve().parent.parent / "deploy" / "bin" / "mc-capture"
    r = subprocess.run(["sh", str(wrapper), "--queue-id=ABCDEF1005"], input=b"x", capture_output=True)
    assert r.returncode == 75   # the capture program is not installed here: deferred, never dropped


def test_capture_is_stdlib_only():
    import ast
    tree = ast.parse(open(capture.__file__).read())
    imported = {n.names[0].name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import)}
    imported |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not imported - {"__future__", "argparse", "errno", "hashlib", "json", "os", "re", "secrets", "socket", "sys",
                           "time"}


# --- storage ----------------------------------------------------------------------

def test_encrypted_store_roundtrip_random_access_and_tamper(tmp_path):
    src = tmp_path / "m.eml"
    data = os.urandom(300_000)
    src.write_bytes(data)
    import hashlib
    sha = hashlib.sha256(data).hexdigest()
    store = blobstore.Store(tmp_path / "store", bytes(32))
    with open(src, "rb") as fh:
        rel, size, encrypted = store.put(fh, len(data), sha)
    assert encrypted and rel.endswith(".enc") and data[:4096] not in (tmp_path / "store" / rel).read_bytes()
    with store.open(rel) as fh:
        fh.seek(200_000)
        assert fh.read(70_000) == data[200_000:270_000]
    assert store.verify(rel, sha)
    path = tmp_path / "store" / rel
    raw = bytearray(path.read_bytes())
    raw[5000] ^= 1
    path.write_bytes(bytes(raw))
    assert not store.verify(rel, sha)
    path.write_bytes(bytes(raw[:-100]))   # truncation
    assert not store.verify(rel, sha)
    with pytest.raises(blobstore.IntegrityError), open(src, "rb") as fh:
        store.put(fh, len(data), "0" * 64)         # wrong hash is refused
    with pytest.raises(blobstore.IntegrityError), open(src, "rb") as fh:
        store.put(fh, len(data), "../../etc/passwd")   # never a path


# --- ingestion, correlation, recipients ---------------------------------------------

def test_capture_ingest_link_and_recipients(db, acfg, store):
    data = make_message()
    spool_capture(acfg, data, "ABCDEF1010", us("2026-10-22T10:00:00.200000"))
    ingest_lines(db, acfg, log_lines("ABCDEF1010", "2026-10-22T10:00:00"))
    stats = ingest_all(db, acfg, store)
    assert stats.ingested == 1 and os.listdir(acfg.archive_spool) == []
    a = db.execute("SELECT * FROM archives").fetchone()
    m = db.execute("SELECT * FROM messages WHERE queue_id = 'ABCDEF1010'").fetchone()
    assert a["message_id"] == m["id"] and a["link_method"] == "archive-delivery"
    assert a["subject"] == "Your verification code" and a["header_message_id"] == "m1@example.com"
    assert a["attachment_count"] == 2 and a["inline_count"] == 1 and a["has_html"] and a["has_text"]
    rcpts = [r[0] for r in db.execute("SELECT address FROM recipients WHERE message_id = ?", (m["id"],))]
    assert rcpts == ["ali@example.org"]          # the archive copy is not a recipient
    assert m["nrcpt"] == 1 and m["status"] == "accepted" and m["archive_status"] == "sent"


def test_large_message_uses_bounded_memory(db, acfg, store):
    m = EmailMessage()
    m["Subject"] = "big"
    m["Message-ID"] = "<big@example.com>"
    m.set_content("see attachment")
    big = os.urandom(12 * 1024 * 1024)
    m.add_attachment(big, maintype="application", subtype="octet-stream", filename="big.bin")
    data = m.as_bytes()
    spool_capture(acfg, data, "ABCDEF1011", us("2026-10-22T10:00:00.200000"))
    del m
    tracemalloc.start()
    ingest_all(db, acfg, store)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 8 * 1024 * 1024, peak   # message is ~16 MiB encoded
    a = archive.get_archive(db, db.execute("SELECT id FROM archives").fetchone()[0])
    part = next(p for p in archive.get_parts(db, a["id"]) if p.filename == "big.bin")
    assert b"".join(archive.stream_part(store, a, part)) == big
    assert b"".join(archive.stream_raw(store, a)) == data


def test_duplicate_delivery_is_archived_once(db, acfg, store):
    data = make_message()
    spool_capture(acfg, data, "ABCDEF1012", us("2026-10-22T10:00:00.200000"))
    spool_capture(acfg, data, "ABCDEF1012", us("2026-10-22T10:00:05.000000"))  # Postfix redelivered the copy
    stats = ingest_all(db, acfg, store)
    assert (stats.ingested, stats.duplicates) == (1, 1)
    assert db.execute("SELECT count(*) FROM archives").fetchone()[0] == 1
    assert os.listdir(acfg.archive_spool) == []


def test_queue_id_reuse_links_each_copy_to_its_own_message(db, acfg, store):
    first = make_message("<first@example.com>", "First", attachments=False)
    second = make_message("<second@example.com>", "Second", attachments=False)
    ingest_lines(db, acfg, log_lines("ABCDEF1013", "2026-10-22T10:00:00", "first@example.com")
                 + log_lines("ABCDEF1013", "2026-10-22T14:00:00", "second@example.com"))
    spool_capture(acfg, first, "ABCDEF1013", us("2026-10-22T10:00:00.200000"))
    spool_capture(acfg, second, "ABCDEF1013", us("2026-10-22T14:00:00.200000"))
    ingest_all(db, acfg, store)
    links = {r["subject"]: r["message_id"] for r in db.execute("SELECT subject, message_id FROM archives")}
    msgs = {r["message_id"]: r["id"] for r in db.execute("SELECT id, message_id FROM messages")}
    assert links == {"First": msgs["first@example.com"], "Second": msgs["second@example.com"]}


def test_missing_and_conflicting_message_ids(db, acfg, store):
    ingest_lines(db, acfg, log_lines("ABCDEF1014", "2026-10-22T10:00:00", None)
                 + log_lines("ABCDEF1015", "2026-10-22T11:00:00", "logged@example.com"))
    spool_capture(acfg, make_message(None, "No id"), "ABCDEF1014", us("2026-10-22T10:00:00.200000"))
    spool_capture(acfg, make_message("<other@example.com>", "Mismatch"), "ABCDEF1015",
                  us("2026-10-22T11:00:00.200000"))
    ingest_all(db, acfg, store)
    rows = {r["subject"]: r for r in db.execute("SELECT * FROM archives")}
    assert rows["No id"]["message_id"] is not None and rows["No id"]["header_message_id"] is None
    assert rows["Mismatch"]["message_id"] is None and rows["Mismatch"]["link_method"] == "conflict"
    assert "differs" in rows["Mismatch"]["link_note"]


def test_capture_before_logs_links_later(db, acfg, store):
    spool_capture(acfg, make_message(), "ABCDEF1016", us("2026-10-22T10:00:00.200000"))
    ingest_all(db, acfg, store)
    assert db.execute("SELECT link_method FROM archives").fetchone()[0] == "pending"
    stats = ingest_lines(db, acfg, log_lines("ABCDEF1016", "2026-10-22T10:00:00"))
    archive.relink(db, stats.queue_ids)
    assert db.execute("SELECT link_method FROM archives").fetchone()[0] == "archive-delivery"


def test_archive_copy_deferral_is_reported_but_not_a_recipient_failure(db, acfg):
    ingest_lines(db, acfg, log_lines("ABCDEF1017", "2026-10-22T10:00:00", archive_ok=False))
    m = db.execute("SELECT * FROM messages WHERE queue_id = 'ABCDEF1017'").fetchone()
    assert m["status"] == "accepted" and m["archive_status"] == "deferred"
    assert db.execute("SELECT count(*) FROM ops_events WHERE message LIKE '%archive copy for ABCDEF1017 deferred%'"
                      ).fetchone()[0] == 1
    assert archive.status(db, acfg)["level"] == "critical"


# --- crash recovery, limits, retention -------------------------------------------------

def test_crash_leftovers_are_recovered(db, acfg, store):
    spool = acfg.archive_spool
    old = time.time() - 7200
    (spool / ".tmp-123-ABCDEF1018-aa").write_bytes(b"partial")
    (spool / "123-ABCDEF1018-bb.eml").write_bytes(b"orphan without json")
    for p in spool.iterdir():
        os.utime(p, (old, old))
    notes = archive.cleanup_spool(acfg)
    assert len(notes) == 2 and os.listdir(spool) == []
    # Stored + recorded but the spool files survived (crash before cleanup): re-run is a no-op.
    data = make_message()
    base = spool_capture(acfg, data, "ABCDEF1019", us("2026-10-22T10:00:00.200000"))
    import shutil
    keep = spool.parent / "keep"
    keep.mkdir()
    for suffix in (".eml", ".json"):
        shutil.copy(spool / f"{base}{suffix}", keep / f"{base}{suffix}")
    ingest_all(db, acfg, store)
    for suffix in (".eml", ".json"):
        shutil.copy(keep / f"{base}{suffix}", spool / f"{base}{suffix}")
    stats = ingest_all(db, acfg, store)
    assert stats.duplicates == 1 and db.execute("SELECT count(*) FROM archives").fetchone()[0] == 1
    assert os.listdir(spool) == []


def test_storage_limit_keeps_captures_in_spool(db, acfg, store):
    spool_capture(acfg, make_message(), "ABCDEF1020", us("2026-10-22T10:00:00.200000"))
    full = dataclasses.replace(acfg, archive_max_bytes=0)
    stats = archive.process_spool(db, full, store)
    assert stats.blocked and "limit" in stats.blocked and len(os.listdir(acfg.archive_spool)) == 2
    low = dataclasses.replace(acfg, archive_min_free_bytes=10 ** 18)
    assert "free" in archive.process_spool(db, low, store).blocked
    assert archive.process_spool(db, acfg, store).ingested == 1


def test_retention_deletes_only_expired_archives(db, acfg, store):
    data = make_message()
    spool_capture(acfg, data, "ABCDEF1021", us("2026-01-01T10:00:00.000000"))
    spool_capture(acfg, make_message("<n@example.com>", "New"), "ABCDEF1022", us("2026-10-22T10:00:00.000000"))
    ingest_all(db, acfg, store)
    now = us("2026-10-25T00:00:00.000000")
    result = archive.apply_retention(db, acfg, store, now=now)
    assert result["archives"] == 1 and result["blobs"] == 1
    assert [r[0] for r in db.execute("SELECT subject FROM archives")] == ["New"]
    assert len(list((acfg.archive_dir).glob("*/*/*"))) == 1


def test_tampered_archive_is_reported_not_rendered(db, acfg, store):
    spool_capture(acfg, make_message(), "ABCDEF1023", us("2026-10-22T10:00:00.200000"))
    ingest_all(db, acfg, store)
    a = archive.get_archive(db, 1)
    path = acfg.archive_dir / a["path"]
    raw = bytearray(path.read_bytes())
    raw[200] ^= 0xFF
    path.write_bytes(bytes(raw))
    view = archive.load_view(db, store, 1)
    assert view["error"] and "authentication" in view["error"]


# --- collector integration ----------------------------------------------------------

def test_collector_ingests_spool_and_links(db, acfg):
    acfg.log_path.write_text("\n".join(log_lines("ABCDEF1024", "2026-10-22T10:00:00")) + "\n")
    spool_capture(acfg, make_message(), "ABCDEF1024", us("2026-10-22T10:00:00.200000"))
    collector = Collector(acfg, enable_monitor=False)
    from mailconsole.collector import make_ingestor
    collector.step(db, make_ingestor(db, acfg))
    collector.archive_step(db)
    assert db.execute("SELECT link_method FROM archives").fetchone()[0] == "archive-delivery"


# --- web: viewing, downloads, isolation, audit ---------------------------------------

@pytest.fixture
def web(acfg, db, admin_client_factory):
    spool_capture(acfg, make_message(), "ABCDEF1030", us("2026-10-22T10:00:00.200000"))
    ingest_lines(db, acfg, log_lines("ABCDEF1030", "2026-10-22T10:00:00"))
    ingest_all(db, acfg, archive.open_store(acfg))
    mid = db.execute("SELECT id FROM messages WHERE queue_id = 'ABCDEF1030'").fetchone()[0]
    return admin_client_factory(acfg), mid


@pytest.fixture
def admin_client_factory(db):
    from fastapi.testclient import TestClient

    from mailconsole import auth
    from mailconsole.web import create_app
    auth.create_admin(db, "admin", PASSWORD)

    def make(cfg):
        client = TestClient(create_app(cfg), base_url="http://127.0.0.1:8710", follow_redirects=False)
        assert login(client).status_code == 303
        return client
    return make


def test_details_show_full_content(web, db):
    client, mid = web
    page = client.get(f"/emails/{mid}").text
    assert "Your verification code" in page
    assert "کد تأیید شما 482913 است." in page and "token=Zz9" in page      # complete, unredacted body
    assert 'dir="auto"' in page and "Message headers" in page and "SMTP envelope" in page
    assert "ali@example.org" in page and "team@example.net" in page        # header Cc vs envelope RCPT
    assert "فاکتور ۱۲.pdf" in page and "evil.html" in page
    assert 'sandbox=""' in page and "/archives/1/preview.html" in page
    assert "<script>alert(1)</script>" not in page
    assert db.execute("SELECT count(*) FROM audit_log WHERE action = 'view_content'").fetchone()[0] == 1


def test_html_preview_is_isolated(web):
    client, _ = web
    r = client.get("/archives/1/preview.html")
    csp = r.headers["content-security-policy"]
    assert csp.startswith("sandbox;") and "script-src" not in csp and "default-src 'none'" in csp
    assert "img-src data:" in csp and "connect-src" not in csp
    assert 'src="data:image/png;base64,' in r.text           # inline image embedded
    assert "cid:logo1" not in r.text and "http-equiv" not in r.text
    assert r.text.startswith('<base target="_blank">')
    assert "https://tracker.example/p.gif" in r.text          # left as-is, blocked by the CSP


def test_raw_and_attachment_downloads(web, db):
    client, _ = web
    raw = client.get("/archives/1/raw.eml")
    assert raw.status_code == 200 and "attachment" in raw.headers["content-disposition"]
    assert raw.headers["content-type"].startswith("message/rfc822")
    view_parts = {p.filename: p.index for p in archive.get_parts(db, 1) if p.filename}
    pdf = client.get(f"/archives/1/parts/{view_parts['فاکتور ۱۲.pdf']}")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-1.4")
    assert pdf.headers["content-type"] == "application/octet-stream"
    assert "filename*=UTF-8''" in pdf.headers["content-disposition"]
    evil = client.get(f"/archives/1/parts/{view_parts['evil.html']}")
    assert evil.headers["content-type"] == "application/octet-stream"
    assert evil.headers["content-disposition"].startswith("attachment;")
    assert evil.headers["content-security-policy"].startswith("sandbox")
    assert client.get("/archives/1/parts/999").status_code == 404


def test_raw_download_is_byte_identical(acfg, db, admin_client_factory):
    data = make_message()
    spool_capture(acfg, data, "ABCDEF1031", us("2026-10-22T10:00:00.200000"))
    ingest_all(db, acfg, archive.open_store(acfg))
    client = admin_client_factory(acfg)
    assert client.get("/archives/1/raw.eml").content == data


def test_downloads_are_audited(web, db):
    client, _ = web
    client.get("/archives/1/raw.eml")
    client.get("/archives/1/parts/5")
    client.get("/archives/1/preview.html")
    actions = [r[0] for r in db.execute("SELECT action FROM audit_log ORDER BY id")]
    assert {"login", "download_eml", "preview_html"} <= set(actions)
    page = client.get("/audit").text
    assert "download eml" in page and "archive:1" in page


def test_content_is_searchable(web):
    client, mid = web
    html = client.get("/emails", params={"range": "custom", "start": "2026-10-01T00:00", "end": "2026-11-01T00:00",
                                         "q": "482913"}).text
    assert f'href="/emails/{mid}"' in html
    html = client.get("/emails", params={"range": "custom", "start": "2026-10-01T00:00", "end": "2026-11-01T00:00",
                                         "q": "فاکتور"}).text
    assert f'href="/emails/{mid}"' in html


def test_messages_without_archive_show_no_invented_content(web, db, acfg):
    client, _ = web
    ingest_lines(db, acfg, log_lines("ABCDEF1032", "2026-10-22T12:00:00"))
    mid = db.execute("SELECT id FROM messages WHERE queue_id = 'ABCDEF1032'").fetchone()[0]
    page = client.get(f"/emails/{mid}").text
    assert "No archived copy." in page and "482913" not in page


def test_unlinked_archive_is_viewable_from_monitoring(acfg, db, admin_client_factory):
    spool_capture(acfg, make_message(), "ABCDEF1033", us("2026-10-22T10:00:00.200000"))
    ingest_all(db, acfg, archive.open_store(acfg))
    client = admin_client_factory(acfg)
    assert "/archives/1" in client.get("/monitoring").text
    page = client.get("/archives/1").text
    assert "not linked to a logged message" in page and "482913" in page


def test_content_routes_require_login(acfg, db):
    from fastapi.testclient import TestClient

    from mailconsole.web import create_app
    spool_capture(acfg, make_message(), "ABCDEF1034", us("2026-10-22T10:00:00.200000"))
    ingest_all(db, acfg, archive.open_store(acfg))
    anon = TestClient(create_app(acfg), base_url="http://127.0.0.1:8710", follow_redirects=False)
    for path in ("/archives/1", "/archives/1/raw.eml", "/archives/1/parts/5", "/archives/1/preview.html", "/audit"):
        r = anon.get(path)
        assert r.status_code == 303 and b"482913" not in r.content and b"%PDF" not in r.content


def test_mime_scanner_handles_rfc2047_and_lf(tmp_path):
    data = make_message()
    s = mime.scan(io.BytesIO(data))
    roles = [p.role for p in s.parts]
    assert roles.count("attachment") == 2 and "body-html" in roles and "inline" in roles
    assert any(p.filename == "فاکتور ۱۲.pdf" for p in s.parts)
    assert re.search(r"verification", s.headers["Subject"])


# --- review regressions ------------------------------------------------------------

def test_hostile_mime_is_archived_raw_and_never_blocks_ingestion(db, acfg, store):
    hostile = b"Content-Type: text/plain " + b"(" * 30000 + b"\nSubject: hostile\n\nbody\n"
    idna = b"Subject: idna\nContent-Type: text/plain; charset=idna\n\nbody\n"
    for i, data in enumerate((hostile, idna, make_message())):
        spool_capture(acfg, data, f"ABCDEF20{i:02d}", us(f"2026-10-22T10:00:0{i}.000000"))
    stats = archive.process_spool(db, acfg, store)
    assert stats.ingested == 3 and stats.quarantined == 0 and os.listdir(acfg.archive_spool) == []
    row = db.execute("SELECT * FROM archives WHERE queue_id = 'ABCDEF2000'").fetchone()
    assert row["subject"] == "hostile"
    a = archive.get_archive(db, row["id"])
    assert b"".join(archive.stream_raw(store, a)) == hostile


def test_untrusted_spool_entries_are_quarantined(db, acfg, store, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("console-only data")
    spool_capture(acfg, make_message(), "ABCDEF2100", us("2026-10-22T10:00:05.000000"))
    # A symlinked .eml (planted by a compromised capture user) and invalid metadata.
    (acfg.archive_spool / "1700000000000000-ABCDEF2101-aaaaaaaa.eml").symlink_to(secret)
    (acfg.archive_spool / "1700000000000000-ABCDEF2101-aaaaaaaa.json").write_text(json.dumps(
        {"queue_id": "ABCDEF2101", "sha256": "a" * 64, "size": 17, "captured_us": 1}))
    (acfg.archive_spool / "1700000000000001-ABCDEF2102-bbbbbbbb.json").write_text(json.dumps(
        {"queue_id": "ABCDEF2102", "sha256": "../../../x", "size": 1, "captured_us": 1}))
    (acfg.archive_spool / "1700000000000001-ABCDEF2102-bbbbbbbb.eml").write_bytes(b"x")
    stats = archive.process_spool(db, acfg, store)
    assert stats.ingested == 1 and stats.quarantined == 2
    assert secret.read_text() == "console-only data"
    assert len(os.listdir(acfg.archive_spool.parent / "quarantine")) == 4


def test_skip_marker_is_recorded_and_shown(db, acfg, store, admin_client_factory):
    capture.main(["--queue-id=ABCDEF2200", f"--spool={acfg.archive_spool}", "--min-free-mb=99999999"],
                 stdin=io.BytesIO(make_message()))
    name = os.listdir(acfg.archive_spool)[0]
    marker = json.loads((acfg.archive_spool / name).read_text())
    marker["captured_us"] = us("2026-10-22T10:00:00.200000")
    (acfg.archive_spool / name).write_text(json.dumps(marker))
    ingest_lines(db, acfg, log_lines("ABCDEF2200", "2026-10-22T10:00:00"))
    stats = archive.process_spool(db, acfg, store)
    archive.relink(db, stats.queue_ids)
    skip = db.execute("SELECT * FROM archive_skips").fetchone()
    mid = db.execute("SELECT id FROM messages WHERE queue_id = 'ABCDEF2200'").fetchone()[0]
    assert skip["message_id"] == mid and os.listdir(acfg.archive_spool) == []
    assert db.execute("SELECT count(*) FROM ops_events WHERE message LIKE '%ABCDEF2200 was NOT archived%'"
                      ).fetchone()[0] == 1
    page = admin_client_factory(acfg).get(f"/emails/{mid}").text
    assert "was not stored" in page and "free disk" in page


def test_missing_copy_is_detected(db, acfg):
    from datetime import datetime, timedelta, timezone
    hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
    ingest_lines(db, acfg, log_lines("ABCDEF2300", hour_ago))
    st = archive.status(db, acfg)
    assert st["missing_7d"] == 1 and st["level"] == "critical"


def test_encryption_required_fails_closed(db, acfg):
    acfg.archive_key_file.unlink()
    plain_store = archive.open_store(acfg)
    spool_capture(acfg, make_message(), "ABCDEF2400", us("2026-10-22T10:00:00.200000"))
    stats = archive.process_spool(db, acfg, plain_store)
    assert stats.blocked and "key" in stats.blocked and len(os.listdir(acfg.archive_spool)) == 2
    off = dataclasses.replace(acfg, archive_encryption="off")
    assert archive.process_spool(db, off, plain_store).ingested == 1


def test_correlation_ignores_previous_lifetime_archive_delivery(db, acfg, store):
    # Same short Queue ID, two lifetimes 30 s apart, copies without Message-ID headers.
    ingest_lines(db, acfg, log_lines("ABCDEF2500", "2026-10-22T10:00:00", None)
                 + log_lines("ABCDEF2500", "2026-10-22T10:00:30", None))
    spool_capture(acfg, make_message(None, "Second", attachments=False), "ABCDEF2500",
                  us("2026-10-22T10:00:30.200000"))
    ingest_all(db, acfg, store)
    second = db.execute("SELECT id FROM messages WHERE queue_id = 'ABCDEF2500' ORDER BY first_ts DESC").fetchone()[0]
    assert db.execute("SELECT message_id FROM archives").fetchone()[0] == second


def test_preview_strips_any_meta_and_filenames_lose_bidi_controls(db, acfg, store, admin_client_factory):
    m = EmailMessage()
    m["Subject"] = "meta"
    m.set_content("x")
    m.add_alternative('<meta data-x=">" http-equiv=refresh content="0;url=https://evil.example/"><p>hi</p>',
                      subtype="html")
    m.add_attachment(b"MZ", maintype="application", subtype="octet-stream", filename="invoice‮fdp.exe")
    spool_capture(acfg, m.as_bytes(), "ABCDEF2600", us("2026-10-22T10:00:00.200000"))
    ingest_all(db, acfg, store)
    client = admin_client_factory(acfg)
    body = client.get("/archives/1/preview.html").text
    assert "evil.example" not in body and "<p>hi</p>" in body
    part = next(p for p in archive.get_parts(db, 1) if p.filename)
    disp = client.get(f"/archives/1/parts/{part.index}").headers["content-disposition"]
    assert "‮" not in disp and "%E2%80%AE" not in disp


def test_size_cap_drops_content_index_before_history(db, acfg, store, monkeypatch):
    from mailconsole import collector as col
    spool_capture(acfg, make_message(), "ABCDEF2700", us("2026-10-22T10:00:00.200000"))
    ingest_lines(db, acfg, log_lines("ABCDEF2700", "2026-10-22T10:00:00"))
    ingest_all(db, acfg, store)
    sizes = iter([10**12, 0, 0, 0])
    monkeypatch.setattr(col, "live_db_bytes", lambda conn: next(sizes, 0))
    result = col.apply_retention(db, dataclasses.replace(acfg, max_db_mb=16), now=us("2026-10-23T00:00:00.000000"))
    assert result["size_cap_unindexed"] == 1 and result["size_cap_trimmed"] == 0
    assert db.execute("SELECT count(*) FROM messages").fetchone()[0] == 1


def test_mime_tolerates_padded_lines_and_exact_64k_header_lines():
    import base64
    data = os.urandom(300)
    perline = b"\n".join(base64.b64encode(data[i:i + 3]) for i in range(0, 300, 3))
    assert b"".join(mime.decode_stream(iter([perline]), "base64")) == data
    long_line = b"X-Long: " + b"a" * (65536 - 8) + b"\nContent-Type: text/html\n\n<b>x</b>\n"
    assert mime.scan(io.BytesIO(long_line)).parts[0].content_type == "text/html"
