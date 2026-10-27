"""Archive ingestion: spool -> blob store -> database, correlation, retention.

Flow for each captured copy (see mailconsole/capture.py for the writer side):

1. ``<base>.json`` in the spool marks a complete capture.
2. The ``.eml`` is copied into the content-addressed store (hash verified,
   fsynced, optionally encrypted). An existing identical blob is reused.
3. Its MIME structure is scanned from the *stored* copy and one database
   transaction records the blob, the archive row, its parts and search text.
   ``UNIQUE(queue_id, sha256)`` makes a repeated delivery a no-op.
4. Only then are the spool files removed. A crash at any point leaves a state
   that the next pass completes or cleans up (see :func:`cleanup_spool`).

Correlation links an archive to a message using the Postfix queue ID passed
by the pipe transport and the capture time, preferably through the logged
delivery of the archive copy itself, and refuses the link when the header
Message-ID contradicts the logged one. Recipient addresses and timestamps
alone are never used.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import mime
from .blobstore import IntegrityError, Store, load_key
from .config import Config
from .db import get_setting, now_us, tx

log = logging.getLogger("mailconsole.archive")

US = 1_000_000
SPOOL_BATCH = 50
STALE_TMP_SECONDS = 3600
TEXT_EXCERPT = 64 * 1024
EVENT_WINDOW_BEFORE = 120 * US
EVENT_WINDOW_AFTER = 600 * US
LIFETIME_SLACK = 120 * US
RELINK_PENDING_DAYS = 7


@dataclass
class ArchiveStats:
    ingested: int = 0
    duplicates: int = 0
    quarantined: int = 0
    errors: list[str] = field(default_factory=list)
    blocked: str | None = None
    queue_ids: set[str] = field(default_factory=set)


def open_store(cfg: Config) -> Store:
    return Store(cfg.archive_dir, load_key(cfg.archive_key_file))


def store_bytes(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT coalesce(sum(stored_size), 0) FROM archive_blobs").fetchone()[0]


def ingest_blocked(conn: sqlite3.Connection, cfg: Config) -> str | None:
    """Reason why new captures must stay in the spool, or None."""
    if store_bytes(conn) >= cfg.archive_max_bytes:
        return (f"archive storage limit reached (MC_ARCHIVE_MAX_GB={cfg.archive_max_bytes // 1024**3}); "
                "captures wait in the spool, nothing is deleted before its retention period")
    cfg.archive_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    free = shutil.disk_usage(cfg.archive_dir).free
    if free < cfg.archive_min_free_bytes:
        return f"only {free // 1024**2} MiB free on the archive disk (MC_ARCHIVE_MIN_FREE_MB)"
    return None


def process_spool(conn: sqlite3.Connection, cfg: Config, store: Store, *, limit: int = SPOOL_BATCH) -> ArchiveStats:
    stats = ArchiveStats()
    spool = cfg.archive_spool
    if not spool.is_dir():
        return stats
    try:
        names = sorted(p.name for p in spool.iterdir() if p.suffix == ".json" and not p.name.startswith("."))
    except OSError as exc:
        stats.errors.append(f"cannot read archive spool: {exc}")
        return stats
    if not names:
        return stats
    stats.blocked = ingest_blocked(conn, cfg)
    if stats.blocked:
        return stats
    for name in names[:limit]:
        meta_path = spool / name
        eml_path = meta_path.with_suffix(".eml")
        try:
            meta = json.loads(meta_path.read_text())
            if not eml_path.exists():
                # Already ingested and the .eml removed before the .json (or lost): drop the marker.
                if conn.execute("SELECT 1 FROM archives WHERE queue_id = ? AND sha256 = ?",
                                (meta["queue_id"], meta["sha256"])).fetchone():
                    meta_path.unlink(missing_ok=True)
                else:
                    stats.errors.append(f"{name}: message file missing")
                continue
            inserted = ingest_one(conn, store, meta, eml_path)
        except IntegrityError as exc:
            quarantine(spool, meta_path, eml_path)
            stats.quarantined += 1
            stats.errors.append(f"{name}: {exc}; moved to quarantine")
            continue
        except (OSError, ValueError, KeyError, sqlite3.DatabaseError) as exc:
            stats.errors.append(f"{name}: {exc.__class__.__name__}: {exc}")
            continue  # left in the spool; retried next pass
        if inserted:
            stats.ingested += 1
        else:
            stats.duplicates += 1
        stats.queue_ids.add(meta["queue_id"])
        meta_path.unlink(missing_ok=True)
        eml_path.unlink(missing_ok=True)
    return stats


def quarantine(spool: Path, *paths: Path) -> None:
    target = spool.parent / "quarantine"
    target.mkdir(exist_ok=True, mode=0o750)
    for p in paths:
        if p.exists():
            os.replace(p, target / p.name)


def ingest_one(conn: sqlite3.Connection, store: Store, meta: dict, eml_path: Path) -> bool:
    """Store one captured message. Returns False if it was already archived."""
    queue_id, sha = str(meta["queue_id"]), str(meta["sha256"])
    if conn.execute("SELECT 1 FROM archives WHERE queue_id = ? AND sha256 = ?", (queue_id, sha)).fetchone():
        return False
    rel, stored_size, encrypted = store.put(eml_path, sha)
    with store.open(rel) as fh:
        scan = mime.scan(fh)
        texts = {}
        for role in ("body-text", "body-html"):
            part = scan.first(role)
            if part is not None:
                texts[role] = mime.decode_text(mime.read_part(fh, part, TEXT_EXCERPT), part.charset)
        decoded_sizes = {}
        for part in scan.parts:
            if part.role in ("attachment", "inline") and part.encoded_size:
                decoded_sizes[part.index] = sum(
                    len(c) for c in mime.decode_stream(mime.iter_range(fh, part.body_start, part.body_end),
                                                       part.transfer_encoding))
    h = scan.headers
    now = now_us()
    with tx(conn):
        conn.execute(
            "INSERT OR IGNORE INTO archive_blobs(sha256, path, size, stored_size, encrypted, created_ts)"
            " VALUES (?, ?, ?, ?, ?, ?)", (sha, rel, int(meta["size"]), stored_size, int(encrypted), now))
        cur = conn.execute(
            "INSERT OR IGNORE INTO archives(queue_id, captured_ts, envelope_sender, sasl_username, host, sha256, size,"
            " header_message_id, subject, from_header, to_header, cc_header, reply_to_header, date_header, has_text,"
            " has_html, attachment_count, inline_count, structure_truncated, created_ts)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (queue_id, int(meta["captured_us"]), meta.get("sender"), meta.get("sasl_username") or None,
             meta.get("host"), sha, int(meta["size"]), _msgid(h.get("Message-ID")), h.get("Subject"), h.get("From"),
             h.get("To"), h.get("Cc"), h.get("Reply-To"), h.get("Date"), int("body-text" in texts),
             int("body-html" in texts), sum(p.role == "attachment" for p in scan.parts),
             sum(p.role == "inline" for p in scan.parts), int(scan.truncated), now))
        if not cur.rowcount:
            return False
        archive_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO archive_parts(archive_id, part_index, parent_index, content_type, charset, transfer_encoding,"
            " disposition, filename, content_id, role, body_start, body_end, decoded_size)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(archive_id, p.index, p.parent, p.content_type, p.charset, p.transfer_encoding, p.disposition,
              p.filename, p.content_id, p.role, p.body_start, p.body_end, decoded_sizes.get(p.index))
             for p in scan.parts])
        doc = " ".join(x for x in [
            h.get("Subject"), h.get("From"), h.get("To"), h.get("Cc"), h.get("Message-ID"),
            " ".join(p.filename for p in scan.parts if p.filename),
            texts.get("body-text") or _strip_tags(texts.get("body-html", "")),
        ] if x)
        conn.execute("INSERT INTO archive_search(rowid, doc) VALUES (?, ?)", (archive_id, doc))
        link_archive(conn, archive_id)
    return True


def _msgid(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    return value[1:-1].strip() if value.startswith("<") and value.endswith(">") else value


def _strip_tags(html: str) -> str:
    import re
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", html)))


# --- correlation ---------------------------------------------------------------

def link_archive(conn: sqlite3.Connection, archive_id: int) -> None:
    """(Re)decide which message an archive belongs to. Caller owns the transaction."""
    a = conn.execute("SELECT * FROM archives WHERE id = ?", (archive_id,)).fetchone()
    if a is None:
        return
    cap = a["captured_ts"]
    target, method, note = None, "pending", None
    # 1. The logged delivery of this very archive copy (same queue file).
    ev = conn.execute(
        "SELECT message_id FROM events WHERE queue_id = ? AND kind = 'archive_delivery' AND message_id IS NOT NULL"
        " AND ts BETWEEN ? AND ? ORDER BY abs(ts - ?) LIMIT 1",
        (a["queue_id"], cap - EVENT_WINDOW_BEFORE, cap + EVENT_WINDOW_AFTER, cap)).fetchone()
    if ev is not None:
        target, method = ev["message_id"], "archive-delivery"
    else:
        # 2. The queue-file lifetime that contains the capture time; ambiguous => wait.
        rows = conn.execute(
            "SELECT id FROM messages WHERE queue_id = ? AND first_ts <= ? AND coalesce(closed_ts, last_ts) + ? >= ?",
            (a["queue_id"], cap + LIFETIME_SLACK, LIFETIME_SLACK, cap)).fetchall()
        if len(rows) == 1:
            target, method = rows[0]["id"], "queue-lifetime"
        elif len(rows) > 1:
            note = "several messages used this Queue ID around the capture time; waiting for more log evidence"
    if target is not None:
        logged = conn.execute("SELECT message_id FROM messages WHERE id = ?", (target,)).fetchone()["message_id"]
        if a["header_message_id"] and logged and a["header_message_id"] != logged:
            target, method = None, "conflict"
            note = (f"header Message-ID <{a['header_message_id']}> differs from the logged <{logged}>; not linked")
        else:
            other = conn.execute(
                "SELECT id FROM archives WHERE message_id = ? AND id != ? AND sha256 != ?",
                (target, archive_id, a["sha256"])).fetchone()
            if other is not None:
                note = "a different archived copy is also linked to this message"
    conn.execute("UPDATE archives SET message_id = ?, link_method = ?, link_note = ? WHERE id = ?",
                 (target, method, note, archive_id))


def relink(conn: sqlite3.Connection, queue_ids: set[str] | None = None) -> int:
    """Re-run correlation for archives of the given queue IDs and for pending ones."""
    ids: set[int] = set()
    if queue_ids:
        for qid in queue_ids:
            ids.update(r[0] for r in conn.execute("SELECT id FROM archives WHERE queue_id = ?", (qid,)))
    since = now_us() - RELINK_PENDING_DAYS * 86400 * US
    ids.update(r[0] for r in conn.execute(
        "SELECT id FROM archives WHERE message_id IS NULL AND link_method != 'conflict' AND captured_ts >= ?"
        " ORDER BY id LIMIT 500", (since,)))
    if ids:
        with tx(conn):
            for archive_id in sorted(ids):
                link_archive(conn, archive_id)
    return len(ids)


# --- maintenance -----------------------------------------------------------------

def cleanup_spool(cfg: Config, now: float | None = None) -> list[str]:
    """Remove leftovers of interrupted captures. Complete captures are never removed."""
    notes: list[str] = []
    spool = cfg.archive_spool
    if not spool.is_dir():
        return notes
    now = now or time.time()
    for p in spool.iterdir():
        try:
            age = now - p.stat().st_mtime
        except FileNotFoundError:
            continue
        if age < STALE_TMP_SECONDS:
            continue
        if p.name.startswith(".tmp-"):
            p.unlink(missing_ok=True)
            notes.append(f"removed interrupted capture {p.name}")
        elif p.suffix == ".eml" and not p.with_suffix(".json").exists():
            # The writer exits successfully only after the .json exists, so Postfix
            # retried this delivery; the orphan is a partial duplicate.
            p.unlink(missing_ok=True)
            notes.append(f"removed incomplete capture {p.name} (Postfix retried it)")
    return notes


def archive_retention_days(conn: sqlite3.Connection, cfg: Config) -> int:
    try:
        return max(1, int(get_setting(conn, "archive_retention_days", str(cfg.archive_retention_days))))
    except ValueError:
        return cfg.archive_retention_days


def apply_retention(conn: sqlite3.Connection, cfg: Config, store: Store, *, now: int | None = None) -> dict:
    """Delete archives older than the archive retention period, then unreferenced blobs."""
    now = now or now_us()
    days = archive_retention_days(conn, cfg)
    cutoff = now - days * 86400 * US
    removed = 0
    while True:
        with tx(conn):
            ids = [r[0] for r in conn.execute(
                "SELECT id FROM archives WHERE captured_ts < ? ORDER BY captured_ts LIMIT 500", (cutoff,))]
            if not ids:
                break
            conn.execute(f"DELETE FROM archives WHERE id IN ({','.join('?' * len(ids))})", ids)
        removed += len(ids)
    blobs = 0
    # Blobs no archive refers to (after retention, or left by a crash between store and DB).
    for sha, rel in conn.execute(
            "SELECT sha256, path FROM archive_blobs WHERE sha256 NOT IN (SELECT sha256 FROM archives)"
    ).fetchall():
        with tx(conn):
            conn.execute("DELETE FROM archive_blobs WHERE sha256 = ?", (sha,))
        store.delete(rel)
        blobs += 1
    _remove_untracked_files(conn, store, now)
    return {"archive_retention_days": days, "archives": removed, "blobs": blobs}


def _remove_untracked_files(conn: sqlite3.Connection, store: Store, now: int) -> None:
    """Delete stored files with no database row that are older than a day (crash leftovers)."""
    known = {r[0] for r in conn.execute("SELECT path FROM archive_blobs")}
    root = store.root
    if not root.is_dir():
        return
    for path in root.glob("*/*/*"):
        rel = path.relative_to(root).as_posix()
        if rel in known:
            continue
        try:
            age = now / US - path.stat().st_mtime
        except FileNotFoundError:
            continue
        if age > 86400:
            path.unlink(missing_ok=True)


def status(conn: sqlite3.Connection, cfg: Config) -> dict:
    """Archive health for the Monitoring page."""
    spool = cfg.archive_spool
    backlog, oldest = 0, None
    if spool.is_dir():
        for p in spool.glob("*.json"):
            backlog += 1
            try:
                mtime = p.stat().st_mtime
            except FileNotFoundError:
                continue
            oldest = mtime if oldest is None else min(oldest, mtime)
    used = store_bytes(conn)
    try:
        disk = shutil.disk_usage(cfg.archive_dir if cfg.archive_dir.exists() else cfg.archive_dir.parent)
        free = disk.free
    except OSError:
        free = None
    row = conn.execute(
        "SELECT count(*), max(captured_ts), sum(message_id IS NULL AND link_method = 'pending'),"
        " sum(link_method = 'conflict') FROM archives").fetchone()
    percent = used * 100 / cfg.archive_max_bytes if cfg.archive_max_bytes else 0
    deferred = conn.execute(
        "SELECT count(*) FROM messages WHERE archive_status IS NOT NULL AND archive_status != 'sent'"
        " AND closed_ts IS NULL").fetchone()[0]
    level = "ok"
    if percent >= 100 or (free is not None and free < cfg.archive_min_free_bytes) or deferred:
        level = "critical"
    elif percent >= cfg.archive_warn_percent or backlog > 100:
        level = "warning"
    return {
        "enabled": cfg.archive_enabled, "spool_exists": spool.is_dir(), "backlog": backlog,
        "oldest_backlog_ts": int(oldest * US) if oldest else None, "used": used,
        "limit": cfg.archive_max_bytes, "percent": percent, "free": free, "archives": row[0] or 0,
        "last_capture_ts": row[1], "pending": row[2] or 0, "conflicts": row[3] or 0,
        "deferred_copies": deferred, "level": level,
        "encrypted": bool(cfg.archive_key_file and cfg.archive_key_file.exists()),
        "retention_days": archive_retention_days(conn, cfg),
    }


# --- viewing ---------------------------------------------------------------------

VIEW_TEXT_LIMIT = 2 * 1024 * 1024


def get_archive(conn: sqlite3.Connection, archive_id: int) -> dict | None:
    row = conn.execute("SELECT a.*, b.path, b.encrypted FROM archives a JOIN archive_blobs b USING (sha256)"
                       " WHERE a.id = ?", (archive_id,)).fetchone()
    return dict(row) if row else None


def get_parts(conn: sqlite3.Connection, archive_id: int) -> list[mime.Part]:
    return [mime.Part(index=r["part_index"], parent=r["parent_index"], depth=0, content_type=r["content_type"],
                      charset=r["charset"], transfer_encoding=r["transfer_encoding"] or "7bit",
                      disposition=r["disposition"], filename=r["filename"], content_id=r["content_id"],
                      header_start=0, body_start=r["body_start"], body_end=r["body_end"],
                      is_multipart=r["role"] == "container", role=r["role"])
            for r in conn.execute("SELECT * FROM archive_parts WHERE archive_id = ? ORDER BY part_index",
                                  (archive_id,))]


def load_view(conn: sqlite3.Connection, store: Store, archive_id: int) -> dict | None:
    """Everything the details page shows for one archived copy (bodies decoded, bounded)."""
    a = get_archive(conn, archive_id)
    if a is None:
        return None
    parts = get_parts(conn, archive_id)
    sizes = {r[0]: r[1] for r in conn.execute(
        "SELECT part_index, decoded_size FROM archive_parts WHERE archive_id = ?", (archive_id,))}
    view = {"archive": a, "parts": parts, "text": None, "text_truncated": False, "has_html": False,
            "headers": "", "attachments": [], "inline": [], "error": None}
    try:
        with store.open(a["path"]) as fh:
            first_body = parts[0].body_start if parts else a["size"]
            fh.seek(0)
            view["headers"] = fh.read(min(first_body, 512 * 1024)).decode("utf-8", "replace")
            text_part = next((p for p in parts if p.role == "body-text"), None)
            if text_part is not None:
                data = mime.read_part(fh, text_part, VIEW_TEXT_LIMIT + 1)
                view["text_truncated"] = len(data) > VIEW_TEXT_LIMIT
                view["text"] = mime.decode_text(data[:VIEW_TEXT_LIMIT], text_part.charset)
    except (IntegrityError, OSError) as exc:
        view["error"] = f"The stored copy could not be read: {exc}"
    view["has_html"] = any(p.role == "body-html" for p in parts)
    for p in parts:
        item = {"index": p.index, "filename": p.filename, "content_type": p.content_type,
                "size": sizes.get(p.index), "content_id": p.content_id}
        if p.role == "attachment":
            view["attachments"].append(item)
        elif p.role == "inline":
            view["inline"].append(item)
    return view


def html_for_preview(conn: sqlite3.Connection, store: Store, archive_id: int, inline_limit: int = 10 * 1024 * 1024
                     ) -> str | None:
    """The HTML body prepared for the sandboxed preview.

    Only this rendering is changed: cid: references become data: URIs (the
    sandbox cannot fetch anything), meta refresh tags are dropped and links
    are pointed at a new window, which the sandbox then blocks. The stored
    original is untouched.
    """
    import base64
    import re
    a = get_archive(conn, archive_id)
    if a is None:
        return None
    parts = get_parts(conn, archive_id)
    html_part = next((p for p in parts if p.role == "body-html"), None)
    if html_part is None:
        return None
    with store.open(a["path"]) as fh:
        html = mime.decode_text(mime.read_part(fh, html_part, VIEW_TEXT_LIMIT), html_part.charset)
        budget = inline_limit
        images = {}
        for p in parts:
            if p.content_id and p.content_type.startswith("image/") and p.encoded_size <= budget:
                data = mime.read_part(fh, p, budget)
                budget -= len(data)
                images[p.content_id.lower()] = f"data:{p.content_type};base64,{base64.b64encode(data).decode()}"

    def cid(match: re.Match) -> str:
        key = match.group(2).strip().lower()
        return match.group(1) + images.get(key, "data:,") + match.group(3)

    html = re.sub(r"""(["'(])cid:([^"')]+)(["')])""", cid, html, flags=re.IGNORECASE)
    html = re.sub(r"<meta\b[^>]*http-equiv[^>]*>", "", html, flags=re.IGNORECASE)
    return '<base target="_blank">' + html


def stream_part(store: Store, archive: dict, part: mime.Part):
    """Yield the decoded bytes of one MIME part (bounded memory)."""
    with store.open(archive["path"]) as fh:
        yield from mime.decode_stream(mime.iter_range(fh, part.body_start, part.body_end), part.transfer_encoding)


def stream_raw(store: Store, archive: dict):
    with store.open(archive["path"]) as fh:
        while True:
            data = fh.read(64 * 1024)
            if not data:
                return
            yield data
