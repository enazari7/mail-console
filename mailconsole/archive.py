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

import errno
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
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
EVENT_SKEW = 2 * US               # clock/order tolerance between capture and Postfix logging
EVENT_WINDOW_AFTER = 600 * US
OPEN_LIFETIME = 6 * 86400 * US    # an unclosed lifetime stays a candidate this long (queue lifetime)
INDEX_BODY_CHARS = 2048
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


def ingest_blocked(conn: sqlite3.Connection, cfg: Config, store: Store) -> str | None:
    """Reason why new captures must stay in the spool, or None."""
    if store.key is None and cfg.archive_encryption == "required":
        return (f"archive encryption key {cfg.archive_key_file} is missing or unreadable; captures wait in the "
                "spool (set MC_ARCHIVE_ENCRYPTION=off only if storing plaintext is intended)")
    if store_bytes(conn) >= cfg.archive_max_bytes:
        return (f"archive storage limit reached (MC_ARCHIVE_MAX_GB={cfg.archive_max_bytes // 1024**3}); "
                "captures wait in the spool, nothing is deleted before its retention period")
    cfg.archive_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    free = shutil.disk_usage(cfg.archive_dir).free
    if free < cfg.archive_min_free_bytes:
        return f"only {free // 1024**2} MiB free on the archive disk (MC_ARCHIVE_MIN_FREE_MB)"
    return None


QUEUE_ID_RE = re.compile(r"^[0-9A-Za-z]{6,20}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
SPOOL_NAME_RE = re.compile(r"^\d{10,20}-[0-9A-Za-z]{6,20}-[0-9a-f]{8}(\.skipped)?\.json$")


class BadCapture(ValueError):
    """Spool metadata that cannot be trusted; the files are quarantined."""


def _open_regular(path: Path):
    """Open a spool file without following symlinks; refuse anything but a regular file."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EISDIR, errno.ENOTDIR, errno.ENXIO):
            raise BadCapture(f"{path.name} is not a regular file") from exc
        raise
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise BadCapture(f"{path.name} is not a regular file")
    return os.fdopen(fd, "rb"), st.st_size


def _load_meta(path: Path) -> dict:
    fh, size = _open_regular(path)
    with fh:
        if size > 64 * 1024:
            raise BadCapture(f"{path.name}: metadata too large")
        meta = json.loads(fh.read())
    try:
        meta["queue_id"] = str(meta["queue_id"])
        meta["sha256"] = str(meta["sha256"])
        meta["size"] = int(meta["size"])
        meta["captured_us"] = int(meta["captured_us"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BadCapture(f"{path.name}: incomplete metadata") from exc
    if not QUEUE_ID_RE.match(meta["queue_id"]) or not SHA_RE.match(meta["sha256"]) or meta["size"] < 0:
        raise BadCapture(f"{path.name}: invalid metadata")
    for key in ("sender", "sasl_username", "host", "skipped"):
        if key in meta and meta[key] is not None:
            meta[key] = str(meta[key])[:500]
    return meta


def process_spool(conn: sqlite3.Connection, cfg: Config, store: Store, *, limit: int = SPOOL_BATCH) -> ArchiveStats:
    stats = ArchiveStats()
    spool = cfg.archive_spool
    if not spool.is_dir():
        return stats
    try:
        names = sorted(p.name for p in spool.iterdir() if SPOOL_NAME_RE.match(p.name))
    except OSError as exc:
        stats.errors.append(f"cannot read archive spool: {exc}")
        return stats
    if not names:
        return stats
    skips = [n for n in names if n.endswith(".skipped.json")]
    captures = [n for n in names if not n.endswith(".skipped.json")]
    for name in skips[:limit]:
        _record_skip(conn, spool / name, stats)
    if not captures:
        return stats
    stats.blocked = ingest_blocked(conn, cfg, store)
    if stats.blocked:
        return stats
    # Archive rows must be durable before the spool files are removed.
    conn.execute("PRAGMA synchronous = FULL")
    try:
        for name in captures[:limit]:
            meta_path = spool / name
            eml_path = meta_path.with_suffix(".eml")
            try:
                meta = _load_meta(meta_path)
                if not eml_path.exists():
                    if conn.execute("SELECT 1 FROM archives WHERE queue_id = ? AND sha256 = ?",
                                    (meta["queue_id"], meta["sha256"])).fetchone():
                        meta_path.unlink(missing_ok=True)   # already ingested; marker left by a crash
                        continue
                    raise BadCapture(f"{name}: message file missing")
                inserted = ingest_one(conn, store, meta, eml_path, index_chars=cfg.archive_index_body_bytes)
            except (OSError, sqlite3.OperationalError) as exc:
                # Environmental (disk, permissions, database busy): leave everything
                # in place and retry on the next pass.
                stats.errors.append(f"{name}: {exc.__class__.__name__}: {exc}")
                break
            except Exception as exc:  # noqa: BLE001 - one bad capture must never block the others
                quarantine(spool, meta_path, eml_path)
                stats.quarantined += 1
                stats.errors.append(f"{name}: {exc.__class__.__name__}: {str(exc)[:200]}; moved to quarantine")
                continue
            if inserted:
                stats.ingested += 1
            else:
                stats.duplicates += 1
            stats.queue_ids.add(meta["queue_id"])
            meta_path.unlink(missing_ok=True)
            eml_path.unlink(missing_ok=True)
    finally:
        conn.execute("PRAGMA synchronous = NORMAL")
    return stats


def _record_skip(conn: sqlite3.Connection, path: Path, stats: ArchiveStats) -> None:
    try:
        meta = _load_meta(path)
        reason = meta.get("skipped") or "skipped"
        with tx(conn):
            cur = conn.execute(
                "INSERT OR IGNORE INTO archive_skips(queue_id, captured_ts, reason, size, sha256, envelope_sender)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (meta["queue_id"], meta["captured_us"], reason, meta["size"], meta["sha256"], meta.get("sender")))
            if cur.rowcount:
                conn.execute(
                    "INSERT OR IGNORE INTO ops_events(ts, host, program, pid, level, message, line_hash)"
                    " VALUES (?, ?, 'mail-console', NULL, 'error', ?, ?)",
                    (meta["captured_us"], meta.get("host"),
                     f"message archive: copy of {meta['queue_id']} was NOT archived: {reason}",
                     bytes.fromhex(meta["sha256"])[:15] + b"S"))
        stats.errors.append(f"copy of {meta['queue_id']} was not archived: {meta.get('skipped')}")
        stats.queue_ids.add(meta["queue_id"])
        path.unlink(missing_ok=True)
    except (OSError, sqlite3.OperationalError):
        return
    except Exception:  # noqa: BLE001
        quarantine(path.parent, path)


def quarantine(spool: Path, *paths: Path) -> None:
    target = spool.parent / "quarantine"
    target.mkdir(exist_ok=True, mode=0o750)
    for p in paths:
        if os.path.lexists(p):
            os.replace(p, target / p.name)


def ingest_one(conn: sqlite3.Connection, store: Store, meta: dict, eml_path: Path,
               index_chars: int = INDEX_BODY_CHARS) -> bool:
    """Store one captured message. Returns False if it was already archived."""
    queue_id, sha = meta["queue_id"], meta["sha256"]
    if conn.execute("SELECT 1 FROM archives WHERE queue_id = ? AND sha256 = ?", (queue_id, sha)).fetchone():
        return False
    fh, size = _open_regular(eml_path)
    with fh:
        rel, stored_size, encrypted = store.put(fh, size, sha)
    scan, texts, decoded_sizes, parse_error = mime.Scan(), {}, {}, None
    try:
        with store.open(rel) as fh:
            scan = mime.scan(fh)
            for role in ("body-text", "body-html"):
                part = scan.first(role)
                if part is not None:
                    texts[role] = mime.decode_text(mime.read_part(fh, part, TEXT_EXCERPT), part.charset)
            for part in scan.parts:
                if part.role in ("attachment", "inline") and part.encoded_size:
                    decoded_sizes[part.index] = sum(
                        len(c) for c in mime.decode_stream(mime.iter_range(fh, part.body_start, part.body_end),
                                                           part.transfer_encoding))
    except IntegrityError:
        raise
    except Exception as exc:  # noqa: BLE001 - keep the raw original even if its structure is unreadable
        scan, texts, decoded_sizes = mime.Scan(), {}, {}
        parse_error = f"{exc.__class__.__name__}: {str(exc)[:200]}"
    h = scan.headers
    now = now_us()
    with tx(conn):
        conn.execute(
            "INSERT OR IGNORE INTO archive_blobs(sha256, path, size, stored_size, encrypted, created_ts)"
            " VALUES (?, ?, ?, ?, ?, ?)", (sha, rel, size, stored_size, int(encrypted), now))
        cur = conn.execute(
            "INSERT OR IGNORE INTO archives(queue_id, captured_ts, envelope_sender, sasl_username, host, sha256, size,"
            " header_message_id, subject, from_header, to_header, cc_header, reply_to_header, date_header, has_text,"
            " has_html, attachment_count, inline_count, structure_truncated, parse_error, created_ts)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (queue_id, meta["captured_us"], meta.get("sender"), meta.get("sasl_username") or None,
             meta.get("host"), sha, size, _msgid(h.get("Message-ID")), h.get("Subject"), h.get("From"),
             h.get("To"), h.get("Cc"), h.get("Reply-To"), h.get("Date"), int("body-text" in texts),
             int("body-html" in texts), sum(p.role == "attachment" for p in scan.parts),
             sum(p.role == "inline" for p in scan.parts), int(scan.truncated), parse_error, now))
        if not cur.rowcount:
            return False
        archive_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO archive_parts(archive_id, part_index, parent_index, content_type, charset, transfer_encoding,"
            " disposition, filename, content_id, role, body_start, body_end, decoded_size)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(archive_id, p.index, p.parent, p.content_type, (p.charset or "")[:40] or None,
              p.transfer_encoding[:40], p.disposition, p.filename, (p.content_id or "")[:300] or None, p.role,
              p.body_start, p.body_end, decoded_sizes.get(p.index)) for p in scan.parts])
        body = texts.get("body-text") or _strip_tags(texts.get("body-html", ""))
        doc = " ".join(x for x in [
            h.get("Subject"), h.get("From"), h.get("To"), h.get("Cc"), h.get("Message-ID"),
            " ".join(p.filename for p in scan.parts if p.filename),
            body[:index_chars],
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
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", html)))


# --- correlation ---------------------------------------------------------------

def link_archive(conn: sqlite3.Connection, archive_id: int) -> None:
    """(Re)decide which message an archive belongs to. Caller owns the transaction."""
    a = conn.execute("SELECT * FROM archives WHERE id = ?", (archive_id,)).fetchone()
    if a is None:
        return
    cap = a["captured_ts"]
    target, method, note = None, "pending", None
    # 1. The logged successful delivery of this very archive copy: the earliest
    #    one at or after the capture (the pipe returns before Postfix logs it).
    ev = conn.execute(
        "SELECT message_id FROM events WHERE queue_id = ? AND kind = 'archive_delivery' AND status = 'sent'"
        " AND message_id IS NOT NULL AND ts BETWEEN ? AND ? ORDER BY ts LIMIT 1",
        (a["queue_id"], cap - EVENT_SKEW, cap + EVENT_WINDOW_AFTER)).fetchone()
    if ev is not None:
        target, method = ev["message_id"], "archive-delivery"
    else:
        # 2. The one queue-file lifetime that was alive at capture time: started
        #    before it and not yet removed (removal comes after the archive copy).
        rows = conn.execute(
            "SELECT id FROM messages WHERE queue_id = ? AND first_ts <= ? AND"
            " (closed_ts IS NULL AND last_ts + ? >= ? OR closed_ts >= ?)",
            (a["queue_id"], cap + EVENT_SKEW, OPEN_LIFETIME, cap, cap - EVENT_SKEW)).fetchall()
        if len(rows) == 1:
            target, method = rows[0]["id"], "queue-lifetime"
        elif len(rows) > 1:
            note = "several messages used this Queue ID around the capture time; waiting for more log evidence"
    if target is not None:
        logged = conn.execute("SELECT message_id FROM messages WHERE id = ?", (target,)).fetchone()["message_id"]
        if a["header_message_id"] and logged and a["header_message_id"] != logged:
            target, method = None, "conflict"
            note = f"header Message-ID <{a['header_message_id']}> differs from the logged <{logged}>; not linked"
        else:
            other = conn.execute(
                "SELECT id FROM archives WHERE message_id = ? AND id != ? AND sha256 != ?",
                (target, archive_id, a["sha256"])).fetchone()
            if other is not None:
                note = "a different archived copy is also linked to this message"
    conn.execute("UPDATE archives SET message_id = ?, link_method = ?, link_note = ? WHERE id = ?",
                 (target, method, note, archive_id))


def _link_skips(conn: sqlite3.Connection, queue_ids: set[str]) -> None:
    for qid in queue_ids:
        for skip in conn.execute("SELECT id, captured_ts FROM archive_skips WHERE queue_id = ?", (qid,)).fetchall():
            row = conn.execute(
                "SELECT id FROM messages WHERE queue_id = ? AND first_ts <= ? AND coalesce(closed_ts, last_ts) + ? >= ?"
                " ORDER BY first_ts DESC LIMIT 1",
                (qid, skip["captured_ts"] + EVENT_SKEW, EVENT_SKEW, skip["captured_ts"])).fetchone()
            conn.execute("UPDATE archive_skips SET message_id = ? WHERE id = ?", (row["id"] if row else None, skip["id"]))


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
    pending_skips = {r[0] for r in conn.execute(
        "SELECT DISTINCT queue_id FROM archive_skips WHERE message_id IS NULL AND captured_ts >= ? LIMIT 500",
        (since,))}
    if ids or queue_ids or pending_skips:
        with tx(conn):
            for archive_id in sorted(ids):
                link_archive(conn, archive_id)
            _link_skips(conn, set(queue_ids or ()) | pending_skips)
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
    with tx(conn):
        conn.execute("DELETE FROM archive_skips WHERE captured_ts < ?", (cutoff,))
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
    now = now_us()
    week = now - 7 * 86400 * US
    skipped = conn.execute("SELECT count(*) FROM archive_skips WHERE captured_ts >= ?", (week,)).fetchone()[0]
    # Copies Postfix delivered to the capture program that never became an
    # archive or a skip record (e.g. the disk was too full to write a marker).
    missing = conn.execute(
        "SELECT count(*) FROM messages m WHERE m.archive_status = 'sent' AND m.archive_ts BETWEEN ? AND ?"
        " AND NOT EXISTS (SELECT 1 FROM archives a WHERE a.message_id = m.id)"
        " AND NOT EXISTS (SELECT 1 FROM archive_skips k WHERE k.message_id = m.id)",
        (week, now - 10 * 60 * US)).fetchone()[0]
    key_missing = cfg.archive_encryption == "required" and not (cfg.archive_key_file and cfg.archive_key_file.exists())
    level = "ok"
    if (percent >= 100 or (free is not None and free < cfg.archive_min_free_bytes) or deferred or skipped
            or missing or (key_missing and spool.is_dir())):
        level = "critical"
    elif percent >= cfg.archive_warn_percent or backlog > 100:
        level = "warning"
    return {
        "enabled": cfg.archive_enabled, "spool_exists": spool.is_dir(), "backlog": backlog,
        "oldest_backlog_ts": int(oldest * US) if oldest else None, "used": used,
        "limit": cfg.archive_max_bytes, "percent": percent, "free": free, "archives": row[0] or 0,
        "last_capture_ts": row[1], "pending": row[2] or 0, "conflicts": row[3] or 0,
        "deferred_copies": deferred, "skipped_7d": skipped, "missing_7d": missing, "key_missing": key_missing,
        "level": level,
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
        item = {"index": p.index, "filename": mime.clean_display(p.filename), "content_type": p.content_type,
                "size": sizes.get(p.index), "content_id": mime.clean_display(p.content_id)}
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
    # Drop every <meta> tag (quoted attributes may contain ">"): no refresh or redirects.
    html = re.sub(r"""<meta\b(?:[^>"']|"[^"]*"|'[^']*')*>""", "", html, flags=re.IGNORECASE)
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
