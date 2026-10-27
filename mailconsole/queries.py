"""Read queries used by the web interface. All functions are side-effect free."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from .db import get_state

US = 1_000_000
HOUR = 3600 * US
DAY = 24 * HOUR

STATUS_LABELS = {
    "accepted": "Accepted",
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
    "accepted": "The next-hop server accepted the message (SMTP 2xx, status=sent). "
                "This does not prove inbox placement, opening or reading.",
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
FILTER_STATUSES = ["accepted", "deferred", "bounced", "expired", "rejected", "failed", "queued", "processing",
                   "removed", "unknown"]


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

@dataclass
class ActivityFilter:
    q: str = ""
    status: str = ""
    domain: str = ""
    start: int | None = None
    end: int | None = None


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _activity_where(f: ActivityFilter) -> tuple[str, list]:
    clauses, args = [], []
    if f.start is not None:
        clauses.append("m.first_ts >= ?")
        args.append(f.start)
    if f.end is not None:
        clauses.append("m.first_ts < ?")
        args.append(f.end)
    if f.status:
        statuses = STATUS_GROUPS.get(f.status, (f.status,))
        clauses.append(f"coalesce(r.status, m.status) IN ({','.join('?' * len(statuses))})")
        args.extend(statuses)
    if f.domain:
        clauses.append("r.domain = ?")
        args.append(f.domain.lower())
    q = f.q.strip()
    if q:
        bare = q[1:-1] if q.startswith("<") and q.endswith(">") else q
        like = _like(bare)
        clauses.append(
            "(m.queue_id = ? OR m.queue_id LIKE ? ESCAPE '\\' OR m.message_id LIKE ? ESCAPE '\\'"
            " OR m.sender LIKE ? ESCAPE '\\' OR r.address LIKE ? ESCAPE '\\' OR r.orig_address LIKE ? ESCAPE '\\'"
            " OR m.sasl_username LIKE ? ESCAPE '\\')"
        )
        args.extend([bare, bare.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%",
                     like, like, like, like, like])
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


def activity(conn: sqlite3.Connection, f: ActivityFilter, page: int, per_page: int) -> dict:
    where, args = _activity_where(f)
    base = " FROM messages m LEFT JOIN recipients r ON r.message_id = m.id" + where
    total = conn.execute("SELECT count(*)" + base, args).fetchone()[0]
    pages = max(1, -(-total // per_page))
    page = min(max(1, page), pages)
    rows = conn.execute(
        "SELECT m.id, m.queue_id, m.first_ts, m.last_ts, m.sender, m.subject, m.status AS message_status, m.nrcpt,"
        " m.origin, r.address, r.domain, r.status AS recipient_status, r.dsn, r.response, r.relay, r.attempts,"
        " coalesce(r.final_ts, r.last_attempt_ts) AS outcome_ts, m.last_response, m.last_dsn" + base +
        " ORDER BY m.first_ts DESC, m.id DESC, r.id LIMIT ? OFFSET ?",
        args + [per_page, (page - 1) * per_page],
    ).fetchall()
    return {"rows": [dict(r) for r in rows], "total": total, "page": page, "pages": pages, "per_page": per_page}


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
        reuse = conn.execute("SELECT count(*) FROM messages WHERE queue_id = ? AND id != ?",
                             (msg["queue_id"], message_id)).fetchone()[0]
    else:
        reuse = 0

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
    return {"message": msg, "recipients": recipients, "events": events, "related": related,
            "reuse_count": reuse, "gaps": gaps}


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
