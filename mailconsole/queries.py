"""Read queries used by the web interface. All functions are side-effect free."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from . import search
from .db import get_state

US = 1_000_000
HOUR = 3600 * US
DAY = 24 * HOUR

STATUS_LABELS = {
    "accepted": "Accepted by destination",
    "deferred": "Deferred",
    "bounced": "Bounced",
    "expired": "Expired",
    "rejected": "Rejected",
    "partial": "Partially failed",
    "queued": "Queued",
    "processing": "Processing",
    "removed": "Removed",
    "discarded": "Discarded",
    "hold": "On hold",
    "unknown": "Unknown",
}
STATUS_HELP = {
    "accepted": "The next-hop SMTP server accepted the message (SMTP 2xx, Postfix status=sent). "
                "This does not prove inbox placement, opening or reading, and a later asynchronous "
                "bounce from the destination is not correlated here yet.",
    "deferred": "Temporary failure (4xx or connection problem). Postfix will retry until the queue lifetime ends.",
    "bounced": "Permanent failure (5xx). Postfix will not retry; a non-delivery notice may have been sent.",
    "expired": "Deferred until the maximum queue lifetime and then returned to the sender.",
    "rejected": "Refused before delivery (SMTP policy, milter or content check).",
    "partial": "Some recipients were accepted and others failed.",
    "queued": "Received by Postfix; the queue manager has not been seen scheduling it yet.",
    "processing": "Scheduled for delivery; no final outcome logged yet for all recipients.",
    "removed": "Removed from the queue without a logged delivery outcome (for example postsuper -d).",
    "discarded": "Discarded by a policy (milter or header/body check).",
    "hold": "Placed on hold in the Postfix queue.",
    "unknown": "The available log evidence does not determine an outcome.",
}
STATUS_GROUPS = {
    "failed": ("bounced", "expired", "rejected"),
}
FILTER_STATUSES = ["queued", "processing", "deferred", "accepted", "bounced", "rejected", "expired", "partial",
                   "unknown", "removed", "failed"]
# Statuses that describe the whole message rather than one recipient.
MESSAGE_LEVEL_STATUSES = {"partial", "processing"}


# --- time ranges -----------------------------------------------------------

@dataclass
class TimeRange:
    key: str
    start: int | None
    end: int | None
    bucket: int
    label: str


RANGE_PRESETS = {
    "1h": (HOUR, 5 * 60 * US, "Last hour"),
    "24h": (DAY, HOUR, "Last 24 hours"),
    "15d": (15 * DAY, DAY, "Last 15 days"),
    "7d": (7 * DAY, 6 * HOUR, "Last 7 days"),
    "30d": (30 * DAY, DAY, "Last 30 days"),
    "90d": (90 * DAY, DAY, "Last 90 days"),
}


def parse_local(value: str | None, tz: ZoneInfo) -> int | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    return int(dt.timestamp() * US)


def resolve_range(key: str | None, start: str | None, end: str | None, tz: ZoneInfo, now: int,
                  *, default: str = "24h", allow_all: bool = False) -> TimeRange:
    key = (key or default).lower()
    if key == "custom":
        s, e = parse_local(start, tz), parse_local(end, tz)
        if s is not None and e is not None and e > s:
            s = max(s, e - 400 * DAY)  # bound the work and the number of chart buckets
            span = e - s
            bucket = (5 * 60 * US if span <= 2 * HOUR else HOUR if span <= 3 * DAY else 6 * HOUR if span <= 10 * DAY
                      else DAY if span <= 120 * DAY else 7 * DAY)
            return TimeRange("custom", s, e, bucket, "Custom range")
        key = default
    if key not in RANGE_PRESETS and not (key == "all" and allow_all):
        key = default
    if key == "all" and allow_all:
        return TimeRange("all", None, None, DAY, "All time")
    span, bucket, label = RANGE_PRESETS.get(key, RANGE_PRESETS["24h"])
    return TimeRange(key if key in RANGE_PRESETS else "24h", now - span, now, bucket, label)


def tz_offset_us(tz: ZoneInfo, at_us: int) -> int:
    offset = datetime.fromtimestamp(at_us / US, tz).utcoffset() or timedelta(0)
    return int(offset.total_seconds() * US)


# --- overview --------------------------------------------------------------

def overview(conn: sqlite3.Connection, rng: TimeRange, tz: ZoneInfo) -> dict:
    s, e = rng.start, rng.end
    one = lambda sql, *args: conn.execute(sql, args).fetchone()[0] or 0  # noqa: E731
    received = one("SELECT count(*) FROM messages WHERE first_ts >= ? AND first_ts < ? AND queue_id IS NOT NULL", s, e)
    accepted = one("SELECT count(*) FROM events WHERE kind = 'delivery' AND status IN ('sent', 'deliverable')"
                   " AND ts >= ? AND ts < ?", s, e)
    deferral_events = one("SELECT count(*) FROM events WHERE kind = 'delivery' AND status = 'deferred'"
                          " AND ts >= ? AND ts < ?", s, e)
    bounced = one("SELECT count(*) FROM events WHERE kind = 'delivery' AND status IN ('bounced', 'undeliverable')"
                  " AND ts >= ? AND ts < ?", s, e)
    expired = one("SELECT count(*) FROM recipients WHERE status = 'expired' AND final_ts >= ? AND final_ts < ?", s, e)
    rejected = one("SELECT count(*) FROM recipients r JOIN messages m ON m.id = r.message_id"
                   " WHERE r.status = 'rejected' AND r.final_ts >= ? AND r.final_ts < ?", s, e)
    deferred_now = one("SELECT count(*) FROM recipients WHERE status = 'deferred'")
    failed = bounced + expired + rejected
    outcomes = accepted + failed
    stats = {
        "received": received, "accepted": accepted, "deferral_events": deferral_events,
        "deferred_now": deferred_now, "bounced": bounced, "expired": expired, "rejected": rejected,
        "failed": failed, "outcomes": outcomes,
        "error_rate": (failed / outcomes) if outcomes else None,
        "deferral_rate": (deferral_events / (accepted + bounced + deferral_events))
        if (accepted + bounced + deferral_events) else None,
    }

    offset = tz_offset_us(tz, e)
    bucket = rng.bucket
    first_bucket = (s + offset) // bucket
    last_bucket = (e - 1 + offset) // bucket
    series = {b: {"accepted": 0, "deferred": 0, "failed": 0} for b in range(first_bucket, last_bucket + 1)}
    rows = conn.execute(
        "SELECT (ts + ?) / ? AS b, CASE WHEN status IN ('sent', 'deliverable') THEN 'accepted'"
        " WHEN status = 'deferred' THEN 'deferred' ELSE 'failed' END AS st, count(*)"
        " FROM events WHERE kind = 'delivery' AND ts >= ? AND ts < ? GROUP BY b, st",
        (offset, bucket, s, e),
    ).fetchall()
    rows += conn.execute(
        "SELECT (final_ts + ?) / ? AS b, 'failed', count(*) FROM recipients"
        " WHERE status IN ('expired', 'rejected') AND final_ts >= ? AND final_ts < ? GROUP BY b",
        (offset, bucket, s, e),
    ).fetchall()
    for b, st, n in rows:
        if b in series:
            series[b][st] += n
    buckets = [{"start": b * bucket - offset, **v} for b, v in sorted(series.items())]

    domains = conn.execute(
        "SELECT coalesce(domain, '(none)') AS domain,"
        " sum(status = 'accepted') AS accepted,"
        " sum(status = 'deferred') AS deferred,"
        " sum(status IN ('bounced', 'expired', 'rejected')) AS failed,"
        " count(*) AS total"
        " FROM recipients WHERE coalesce(final_ts, last_attempt_ts) >= ? AND coalesce(final_ts, last_attempt_ts) < ?"
        " GROUP BY domain ORDER BY total DESC, domain LIMIT 10",
        (s, e),
    ).fetchall()
    recent_failures = conn.execute(
        "SELECT m.id, m.queue_id, m.sender, r.address, r.status, r.dsn, r.response,"
        " coalesce(r.final_ts, r.last_attempt_ts) AS ts"
        " FROM recipients r JOIN messages m ON m.id = r.message_id"
        " WHERE r.status IN ('bounced', 'expired', 'rejected', 'deferred')"
        " AND coalesce(r.final_ts, r.last_attempt_ts) >= ? AND coalesce(r.final_ts, r.last_attempt_ts) < ?"
        " ORDER BY ts DESC LIMIT 8",
        (s, e),
    ).fetchall()
    return {"stats": stats, "buckets": buckets, "domains": [dict(r) for r in domains],
            "recent_failures": [dict(r) for r in recent_failures], "queue": latest_queue(conn),
            "queue_history": queue_history(conn, max(s, e - DAY), e)}


# --- activity --------------------------------------------------------------

MAX_COUNT = 10_000          # counts above this are shown as "10,000+"
SORTS = {
    "sent": "m.first_ts {d}, m.id {d}, r.id {d}",
    "recipient": "r.address COLLATE NOCASE {d}, m.first_ts DESC, m.id DESC, r.id",
    "status": "row_status {d}, m.first_ts DESC, m.id DESC, r.id",
}
ROW_COLUMNS = (
    "m.id, m.queue_id, m.first_ts, m.last_ts, m.sender,"
    " coalesce(m.subject, (SELECT a.subject FROM archives a WHERE a.message_id = m.id ORDER BY a.id LIMIT 1))"
    " AS subject,"
    " EXISTS (SELECT 1 FROM archives a WHERE a.message_id = m.id) AS archived,"
    " m.message_id, m.status AS message_status,"
    " m.nrcpt, m.origin, r.address, r.domain, r.status AS recipient_status, r.dsn, r.response, r.relay,"
    " r.attempts, coalesce(r.final_ts, r.last_attempt_ts) AS outcome_ts, m.last_response, m.last_dsn,"
    " coalesce(r.status, m.status) AS row_status"
)


@dataclass
class ActivityFilter:
    q: str = ""
    status: str = ""
    domain: str = ""
    sender: str | None = None     # None = any sender; "" = null sender <>
    start: int | None = None
    end: int | None = None
    sort: str = "sent"
    direction: str = "desc"

    @property
    def term(self) -> str:
        q = self.q.replace("\x00", "").strip()
        return q[1:-1].strip() if q.startswith("<") and q.endswith(">") else q

    @property
    def short_term(self) -> bool:
        return 0 < len(self.term) < search.MIN_SUBSTRING


def _row_text(prefix_cols: list[str]) -> str:
    return "mc_fold(" + " || ' ' || ".join(f"coalesce({c}, '')" for c in prefix_cols) + ")"


def _activity_where(f: ActivityFilter) -> tuple[str, list]:
    """WHERE clause shared by the list, the count and the export. All values are bound parameters."""
    clauses, args = [], []
    if f.start is not None:
        clauses.append("m.first_ts >= ?")
        args.append(f.start)
    if f.end is not None:
        clauses.append("m.first_ts < ?")
        args.append(f.end)
    if f.status:
        if f.status in MESSAGE_LEVEL_STATUSES:
            clauses.append("m.status = ?")
            args.append(f.status)
        else:
            statuses = STATUS_GROUPS.get(f.status, (f.status,))
            clauses.append(f"coalesce(r.status, m.status) IN ({','.join('?' * len(statuses))})")
            args.extend(statuses)
    if f.domain:
        clauses.append("r.domain = ?")
        args.append(f.domain.lower())
    if f.sender is not None:
        clauses.append("m.sender = ? COLLATE NOCASE")
        args.append(f.sender)
    term = f.term
    if term and len(term) >= search.MIN_SUBSTRING:
        # 1) indexed candidate messages from the trigram FTS index,
        # 2) row-level check so a recipient row is shown only if the term is in
        #    a message-wide field or in that recipient's own fields.
        message_text = _row_text(["m.queue_id", "m.sender", "m.message_id", "m.subject", "m.sasl_username"])
        recipient_text = _row_text(["r.address", "r.orig_address", "r.domain",
                                    "CASE WHEN r.status != 'accepted' THEN r.response END"])
        # Log metadata (row-level), or archived content (subject, header
        # addresses, attachment names, body text) of the whole message.
        clauses.append(
            "((m.id IN (SELECT rowid FROM message_search WHERE message_search MATCH ?)"
            f" AND (instr({message_text}, ?) > 0 OR instr({recipient_text}, ?) > 0"
            " OR (r.id IS NULL AND instr(mc_fold(coalesce(m.last_response, '')), ?) > 0)))"
            " OR m.id IN (SELECT message_id FROM archives WHERE message_id IS NOT NULL AND id IN"
            " (SELECT rowid FROM archive_search WHERE archive_search MATCH ?)))")
        args.extend([search.phrase(term)] + [search.fold(term)] * 3 + [search.phrase(term)])
    elif term:
        # Too short for substring search: exact, indexed matches only.
        clauses.append("(m.queue_id = ? OR r.domain = ? OR r.address = ? COLLATE NOCASE)")
        args.extend([term, term.lower(), term])
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


def _order(f: ActivityFilter) -> str:
    direction = "ASC" if f.direction == "asc" else "DESC"
    return SORTS.get(f.sort, SORTS["sent"]).format(d=direction)


BASE_FROM = " FROM messages m LEFT JOIN recipients r ON r.message_id = m.id"


def activity(conn: sqlite3.Connection, f: ActivityFilter, page: int, per_page: int) -> dict:
    where, args = _activity_where(f)
    total = conn.execute(f"SELECT count(*) FROM (SELECT 1{BASE_FROM}{where} LIMIT ?)",
                         args + [MAX_COUNT + 1]).fetchone()[0]
    capped = total > MAX_COUNT
    total = min(total, MAX_COUNT)
    pages = max(1, -(-total // per_page))
    page = min(max(1, page), pages)
    rows = conn.execute(
        f"SELECT {ROW_COLUMNS}{BASE_FROM}{where} ORDER BY {_order(f)} LIMIT ? OFFSET ?",
        args + [per_page, (page - 1) * per_page],
    ).fetchall()
    return {"rows": [dict(r) for r in rows], "total": total, "capped": capped, "page": page, "pages": pages,
            "per_page": per_page}


def export_rows(conn: sqlite3.Connection, f: ActivityFilter, limit: int):
    """Yield up to ``limit`` rows of the filtered result set, in display order."""
    where, args = _activity_where(f)
    cur = conn.execute(f"SELECT {ROW_COLUMNS}{BASE_FROM}{where} ORDER BY {_order(f)} LIMIT ?", args + [limit])
    while True:
        batch = cur.fetchmany(500)
        if not batch:
            return
        yield from batch


def count_rows(conn: sqlite3.Connection, f: ActivityFilter, cap: int) -> int:
    where, args = _activity_where(f)
    return conn.execute(f"SELECT count(*) FROM (SELECT 1{BASE_FROM}{where} LIMIT ?)", args + [cap]).fetchone()[0]


def senders(conn: sqlite3.Connection, start: int | None, end: int | None, limit: int = 100) -> list[dict]:
    """Sender addresses seen in the range, most frequent first."""
    clauses, args = ["sender IS NOT NULL", "queue_id IS NOT NULL"], []
    if start is not None:
        clauses.append("first_ts >= ?")
        args.append(start)
    if end is not None:
        clauses.append("first_ts < ?")
        args.append(end)
    rows = conn.execute(
        f"SELECT sender, count(*) AS n FROM messages WHERE {' AND '.join(clauses)}"
        " GROUP BY sender ORDER BY n DESC, sender LIMIT ?", args + [limit]).fetchall()
    return [dict(r) for r in rows]


# --- details ---------------------------------------------------------------

def message_detail(conn: sqlite3.Connection, message_id: int) -> dict | None:
    msg = conn.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
    if msg is None:
        return None
    msg = dict(msg)
    recipients = [dict(r) for r in conn.execute(
        "SELECT * FROM recipients WHERE message_id = ? ORDER BY address", (message_id,))]
    events = []
    for e in conn.execute("SELECT * FROM events WHERE message_id = ? ORDER BY ts, id", (message_id,)):
        e = dict(e)
        e["detail"] = json.loads(e["detail"]) if e["detail"] else {}
        events.append(e)

    related = []
    if msg["notification_qid"]:
        child = conn.execute(
            "SELECT id, queue_id, status, first_ts FROM messages WHERE queue_id = ? AND first_ts BETWEEN ? AND ?"
            " ORDER BY abs(first_ts - ?) LIMIT 1",
            (msg["notification_qid"], msg["last_ts"] - 60 * US, msg["last_ts"] + 60 * US, msg["last_ts"]),
        ).fetchone()
        related.append({"relation": "Non-delivery notice generated by Postfix", "queue_id": msg["notification_qid"],
                        "id": child["id"] if child else None, "status": child["status"] if child else None})
    if msg["queue_id"] and msg["origin"] == "dsn":
        parent = conn.execute(
            "SELECT id, queue_id, status FROM messages WHERE notification_qid = ? AND last_ts BETWEEN ? AND ?"
            " ORDER BY abs(last_ts - ?) LIMIT 1",
            (msg["queue_id"], msg["first_ts"] - 60 * US, msg["first_ts"] + 60 * US, msg["first_ts"]),
        ).fetchone()
        if parent:
            related.append({"relation": "Notice about original message", "queue_id": parent["queue_id"],
                            "id": parent["id"], "status": parent["status"]})
    for e in events:
        handoff = e["detail"].get("queued_as")
        if handoff and e["status"] == "sent":
            nxt = conn.execute(
                "SELECT id, status FROM messages WHERE queue_id = ? AND first_ts BETWEEN ? AND ?"
                " ORDER BY abs(first_ts - ?) LIMIT 1",
                (handoff, e["ts"] - 60 * US, e["ts"] + 60 * US, e["ts"])).fetchone()
            related.append({"relation": f"Handed to local relay {e['relay']}; continues as",
                            "queue_id": handoff, "id": nxt["id"] if nxt else None,
                            "status": nxt["status"] if nxt else None})
    if msg["orig_queue_id"]:
        prev = conn.execute(
            "SELECT id, status FROM messages WHERE queue_id = ? AND first_ts <= ? ORDER BY first_ts DESC LIMIT 1",
            (msg["orig_queue_id"], msg["first_ts"]),
        ).fetchone()
        related.append({"relation": "Requeued from", "queue_id": msg["orig_queue_id"],
                        "id": prev["id"] if prev else None, "status": prev["status"] if prev else None})
    if msg["queue_id"]:
        requeued_as = conn.execute(
            "SELECT id, queue_id, status FROM messages WHERE orig_queue_id = ? AND first_ts >= ?"
            " ORDER BY first_ts LIMIT 1", (msg["queue_id"], msg["first_ts"])).fetchone()
        if requeued_as:
            related.append({"relation": "Requeued as", "queue_id": requeued_as["queue_id"],
                            "id": requeued_as["id"], "status": requeued_as["status"]})
        reuse, reuse_first = conn.execute("SELECT count(*) - 1, min(first_ts) FROM messages WHERE queue_id = ?",
                                          (msg["queue_id"],)).fetchone()
    else:
        reuse, reuse_first = 0, None

    gaps = []
    if not msg["has_start"] and msg["origin"] not in ("dsn",):
        gaps.append("No submission record (smtpd client= or pickup) was found; the message may predate the "
                    "available logs.")
    if not msg["has_qmgr"] and msg["status"] not in ("rejected", "discarded"):
        gaps.append("The queue manager never logged this message as active; sender and recipient count may be "
                    "unknown.")
    if msg["closed_ts"] is None and msg["status"] not in ("rejected", "discarded"):
        gaps.append("No 'removed' record yet: the message may still be in the queue, or later log lines are "
                    "not available.")
    if msg["nrcpt"] and len(recipients) < msg["nrcpt"]:
        gaps.append(f"Postfix reported {msg['nrcpt']} recipient(s); {len(recipients)} appear in delivery records.")
    if msg["events_truncated"]:
        gaps.append("This message exceeded the per-message event limit; some retry events were not stored, so "
                    "retry counts are lower bounds.")
    skips = [dict(r) for r in conn.execute(
        "SELECT captured_ts, reason, size FROM archive_skips WHERE message_id = ? ORDER BY captured_ts", (message_id,))]
    archives = [dict(r) for r in conn.execute(
        "SELECT id, captured_ts, link_method, link_note, sha256, size FROM archives WHERE message_id = ?"
        " ORDER BY captured_ts, id", (message_id,))]
    finals = [r["final_ts"] for r in recipients if r["final_ts"]]
    summary = {
        "attempts": sum(r["attempts"] for r in recipients),
        "deferrals": sum(r["deferrals"] for r in recipients),
        "final_ts": max(finals) if finals and len(finals) == len(recipients) else None,
        "relays": sorted({r["relay"] for r in recipients if r["relay"]}),
        "dsns": sorted({r["dsn"] for r in recipients if r["dsn"]}),
    }
    return {"message": msg, "recipients": recipients, "events": events, "related": related,
            "reuse_count": reuse, "reuse_first_ts": reuse_first, "gaps": gaps, "archives": archives, "skips": skips,
            "summary": summary}


def resolve_queue_id(conn: sqlite3.Connection, queue_id: str) -> int | None:
    row = conn.execute("SELECT id FROM messages WHERE queue_id = ? ORDER BY first_ts DESC LIMIT 1",
                       (queue_id,)).fetchone()
    return row[0] if row else None


# --- monitoring ------------------------------------------------------------

def latest_queue(conn: sqlite3.Connection) -> dict | None:
    row = conn.execute("SELECT * FROM queue_snapshots ORDER BY id DESC LIMIT 1").fetchone()
    if row is None:
        return None
    snap = dict(row)
    snap["by_queue"] = json.loads(snap["by_queue"] or "{}")
    snap["entries"] = json.loads(snap["entries"] or "[]")
    return snap


def queue_history(conn: sqlite3.Connection, start: int, end: int, points: int = 96) -> list[dict]:
    rows = conn.execute("SELECT ts, total FROM queue_snapshots WHERE ok = 1 AND ts >= ? AND ts < ? ORDER BY ts",
                        (start, end)).fetchall()
    if len(rows) > points:
        step = len(rows) / points
        rows = [rows[int(i * step)] for i in range(points)] + [rows[-1]]
    return [{"ts": r[0], "total": r[1]} for r in rows]


def monitoring(conn: sqlite3.Connection, db_path, now: int, ops_level: str = "") -> dict:
    services = [dict(r) for r in conn.execute("SELECT * FROM service_status ORDER BY rowid")]
    state = {r[0]: r[1] for r in conn.execute("SELECT key, value FROM collector_state")}
    heartbeat = int(state.get("collector_heartbeat_ts", "0") or 0)
    checkpoints = [dict(r) for r in conn.execute("SELECT source, path, inode, offset, cursor, updated_ts FROM checkpoints")]
    args: list = []
    level_clause = ""
    if ops_level:
        level_clause = " WHERE level = ?"
        args.append(ops_level)
    ops = [dict(r) for r in conn.execute(
        f"SELECT ts, host, program, pid, level, message FROM ops_events{level_clause} ORDER BY ts DESC, id DESC LIMIT 100",
        args)]
    try:
        db_size = sum(os.path.getsize(str(db_path) + s) for s in ("", "-wal") if os.path.exists(str(db_path) + s))
    except OSError:
        db_size = None
    counts = conn.execute("SELECT count(*), min(first_ts) FROM messages").fetchone()
    return {
        "services": services,
        "queue": latest_queue(conn),
        "queue_history": queue_history(conn, now - DAY, now + 1),
        "collector": {
            "heartbeat_ts": heartbeat or None,
            "alive": bool(heartbeat) and now - heartbeat < 90 * US,
            "started_ts": int(state.get("collector_started_ts", "0") or 0) or None,
            "source": state.get("collector_source"),
            "last_log_ts": int(state.get("last_log_ts", "0") or 0) or None,
            "lines_total": int(state.get("lines_total", "0") or 0),
            "events_total": int(state.get("events_total", "0") or 0),
            "duplicates_total": int(state.get("duplicates_total", "0") or 0),
            "last_maintenance_ts": int(state.get("last_maintenance_ts", "0") or 0) or None,
            "checkpoints": checkpoints,
        },
        "ops": ops,
        "db": {"size": db_size, "messages": counts[0], "oldest_ts": counts[1]},
        "stale_services": any(now - s["checked_ts"] > 180 * US for s in services),
    }


def collector_alive(conn: sqlite3.Connection, now: int) -> bool:
    heartbeat = int(get_state(conn, "collector_heartbeat_ts", "0") or 0)
    return bool(heartbeat) and now - heartbeat < 90 * US
