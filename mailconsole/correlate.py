"""Store classified log records and correlate them into messages.

Design:

* ``events`` is the source of truth. Every stored event carries a hash of
  its log line, so re-reading a line is a no-op (idempotent ingestion).
* A *message* is one lifetime of a Postfix queue file. Short queue IDs are
  reused by Postfix, so a queue ID alone does not identify a message. An
  event joins an existing message only when the evidence allows it; see
  :meth:`Ingestor._assign`.
* Message and recipient state is *derived*: after each batch every touched
  message is recomputed from its stored events. This keeps results
  independent of ingestion order and makes duplicate input harmless.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Iterable

from .parser import Classified, redact

SKEW_US = 2_000_000          # tolerated clock/order skew between daemons
START_KINDS = {"connect", "pickup"}
CLOSE_KINDS = {"removed", "requeued"}
# Events that may be dropped once a message reaches the per-message cap.
DROPPABLE = {"queued", "other", "milter_info"}

ACCEPTED = "accepted"
FAILED_STATES = {"bounced", "expired", "rejected"}
FINAL_STATES = {ACCEPTED} | FAILED_STATES | {"removed", "discarded"}

DELIVERY_STATUS_MAP = {
    "sent": "accepted",
    "deliverable": "accepted",      # address verification probe
    "deferred": "deferred",
    "bounced": "bounced",
    "undeliverable": "bounced",     # address verification probe
    "expired": "expired",
}


@dataclass
class IngestStats:
    lines: int = 0
    events: int = 0
    duplicates: int = 0
    ops: int = 0
    dropped: int = 0
    messages_touched: set[int] = field(default_factory=set)

    def merge(self, other: "IngestStats") -> None:
        self.lines += other.lines
        self.events += other.events
        self.duplicates += other.duplicates
        self.ops += other.ops
        self.dropped += other.dropped
        self.messages_touched |= other.messages_touched


def _domain(address: str) -> str | None:
    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower() or None


class Ingestor:
    def __init__(self, conn: sqlite3.Connection, *, reuse_gap_hours: int = 144,
                 max_events_per_message: int = 2000, store_raw: bool = True):
        self.conn = conn
        self.gap_us = reuse_gap_hours * 3600 * 1_000_000
        self.max_events = max_events_per_message
        self.store_raw = store_raw

    # -- public -----------------------------------------------------------

    def ingest(self, items: Iterable[Classified]) -> IngestStats:
        """Ingest classified records. The caller owns the transaction."""
        stats = IngestStats()
        for item in items:
            stats.lines += 1
            if item.ops is not None:
                self._store_ops(item, stats)
            elif item.event is not None:
                self._store_event(item, stats)
        for message_id in sorted(stats.messages_touched):
            recompute_message(self.conn, message_id)
        self._link_notifications(stats.messages_touched)
        return stats

    def _link_notifications(self, message_ids: set[int]) -> None:
        """Mark DSNs that Postfix generated (bounce/expiry notices) as such."""
        if not message_ids:
            return
        marks = ",".join("?" * len(message_ids))
        parents = self.conn.execute(
            f"SELECT id, notification_qid, last_ts, host FROM messages WHERE id IN ({marks})"
            " AND notification_qid IS NOT NULL", sorted(message_ids)).fetchall()
        for parent in parents:
            self.conn.execute(
                "UPDATE messages SET origin = 'dsn' WHERE queue_id = ? AND has_start = 0 AND origin = 'unknown'"
                " AND host IS ? AND first_ts BETWEEN ? AND ?",
                (parent["notification_qid"], parent["host"], parent["last_ts"] - 60_000_000,
                 parent["last_ts"] + 60_000_000),
            )

    # -- internals --------------------------------------------------------

    def _store_ops(self, item: Classified, stats: IngestStats, level: str | None = None) -> None:
        rec = item.record
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO ops_events(ts, host, program, pid, level, message, line_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (rec.ts, rec.host, rec.program, rec.pid, level or item.ops.level,
             redact(item.ops.message if item.ops else rec.message)[:4000], rec.line_hash),
        )
        if cur.rowcount:
            stats.ops += 1
        else:
            stats.duplicates += 1

    def _store_event(self, item: Classified, stats: IngestStats) -> None:
        rec, ev = item.record, item.event
        line_hash = rec.line_hash
        if self.conn.execute("SELECT 1 FROM events WHERE line_hash = ?", (line_hash,)).fetchone():
            stats.duplicates += 1
            return

        if ev.queue_id is None:
            message_id = self._new_message(None, rec.host, rec.ts, origin="noqueue")
        else:
            message_id = self._assign(ev.queue_id, rec.ts, ev.kind, rec.host, create=not item.attach_only)
            if message_id is None:
                # Milter/DKIM info for a queue ID we have no open message for:
                # keep it as an operational note only when it reports a problem.
                if ev.detail.get("level"):
                    item.ops = None
                    self._store_ops(item, stats, level="error")
                return

        count, truncated = self.conn.execute(
            "SELECT event_count, events_truncated FROM messages WHERE id = ?", (message_id,)
        ).fetchone()
        droppable = ev.kind in DROPPABLE or (ev.kind == "delivery" and ev.status == "deferred")
        if count >= self.max_events and droppable:
            if not truncated:
                self.conn.execute("UPDATE messages SET events_truncated = 1 WHERE id = ?", (message_id,))
            stats.dropped += 1
            stats.messages_touched.add(message_id)
            return

        self.conn.execute(
            "INSERT INTO events(message_id, ts, host, program, pid, queue_id, kind, recipient, status, dsn,"
            " relay, delay, delays, response, detail, raw, line_hash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                message_id, rec.ts, rec.host, rec.program, rec.pid, ev.queue_id, ev.kind,
                ev.recipient, ev.status, ev.dsn, ev.relay, ev.delay, ev.delays,
                redact(ev.response) if ev.response else None,
                json.dumps(_detail(ev), separators=(",", ":")) if _detail(ev) else None,
                redact(rec.raw)[:8000] if self.store_raw else None,
                line_hash,
            ),
        )
        self.conn.execute("UPDATE messages SET event_count = event_count + 1 WHERE id = ?", (message_id,))
        stats.events += 1
        stats.messages_touched.add(message_id)

    def _new_message(self, queue_id: str | None, host: str, ts: int, origin: str = "unknown") -> int:
        cur = self.conn.execute(
            "INSERT INTO messages(queue_id, host, first_ts, last_ts, origin, status) VALUES (?, ?, ?, ?, ?, 'unknown')",
            (queue_id, host, ts, ts, origin),
        )
        return cur.lastrowid

    def _assign(self, qid: str, ts: int, kind: str, host: str, *, create: bool) -> int | None:
        """Find the message instance an event belongs to, or start a new one.

        Rules (an event joins an instance only if none of these is violated):

        1. The instance must have started no later than the event (with skew).
        2. A closed instance (``removed``/``requeued`` seen) accepts no later events.
        3. An instance has exactly one start event (smtpd ``client=`` /
           pickup ``uid=``); a second start means the queue ID was reused.
        4. A silence longer than the reuse gap means a different message.

        Out-of-order arrivals (an older log imported later) may join the next
        instance when that instance has no start event of its own.
        """
        rows = self.conn.execute(
            "SELECT id, first_ts, last_ts, has_start, closed_ts, host FROM messages"
            " WHERE queue_id = ? ORDER BY first_ts DESC LIMIT 8",
            (qid,),
        ).fetchall()
        rows = [r for r in rows if r["host"] in (None, host)]
        is_start = kind in START_KINDS

        target = None
        candidate = next((r for r in rows if r["first_ts"] <= ts + SKEW_US), None)
        if candidate is not None:
            ok = True
            if candidate["closed_ts"] is not None and ts > candidate["closed_ts"]:
                ok = False
            if is_start and (candidate["has_start"] or ts > candidate["first_ts"] + SKEW_US):
                ok = False
            if ts - candidate["last_ts"] > self.gap_us:
                ok = False
            if ok:
                target = candidate
        else:
            later = min(rows, key=lambda r: r["first_ts"]) if rows else None
            if later is not None and not later["has_start"] and later["first_ts"] - ts <= self.gap_us:
                target = later

        if target is None:
            if not create:
                return None
            message_id = self._new_message(qid, host, ts)
            target_first = target_last = ts
        else:
            message_id = target["id"]
            target_first, target_last = target["first_ts"], target["last_ts"]

        updates = {"first_ts": min(target_first, ts), "last_ts": max(target_last, ts)}
        sets = "first_ts = ?, last_ts = ?"
        params: list = [updates["first_ts"], updates["last_ts"]]
        if is_start:
            sets += ", has_start = 1"
        if kind in CLOSE_KINDS:
            sets += ", closed_ts = max(coalesce(closed_ts, 0), ?)"
            params.append(ts)
        params.append(message_id)
        self.conn.execute(f"UPDATE messages SET {sets} WHERE id = ?", params)
        return message_id


def _detail(ev) -> dict:
    detail = {k: v for k, v in ev.detail.items() if v not in (None, "", {})}
    if ev.orig_recipient:
        detail["orig_to"] = ev.orig_recipient
    if "text" in detail:
        detail["text"] = redact(detail["text"])
    return detail


# --- derived state ---------------------------------------------------------

def recompute_message(conn: sqlite3.Connection, message_id: int) -> None:
    """Rebuild a message's summary and recipient rows from its events."""
    events = conn.execute(
        "SELECT * FROM events WHERE message_id = ? ORDER BY ts, id", (message_id,)
    ).fetchall()
    msg = conn.execute("SELECT origin, closed_ts FROM messages WHERE id = ?", (message_id,)).fetchone()
    if msg is None:
        return

    summary: dict = {
        "sender": None, "message_id": None, "subject": None, "size": None, "nrcpt": None,
        "client": None, "sasl_username": None, "orig_queue_id": None, "notification_qid": None,
        "has_start": 0, "has_qmgr": 0, "active_count": 0, "last_dsn": None, "last_response": None,
    }
    origin = msg["origin"] if msg["origin"] in ("noqueue", "dsn") else "unknown"
    recipients: dict[str, dict] = {}
    closed_ts = None
    expired_ts = None
    rejected = discarded = False
    on_hold = False
    queued_seen = False
    sender_sources: dict[str, str] = {}
    first_ts = events[0]["ts"] if events else None
    last_ts = events[-1]["ts"] if events else None

    def rcpt(address: str, orig: str | None = None) -> dict:
        r = recipients.get(address)
        if r is None:
            r = recipients[address] = {
                "address": address, "orig_address": orig, "domain": _domain(address), "status": "unknown",
                "dsn": None, "relay": None, "response": None, "delay": None, "delays": None,
                "attempts": 0, "deferrals": 0, "first_attempt_ts": None, "last_attempt_ts": None, "final_ts": None,
            }
        elif orig and not r["orig_address"]:
            r["orig_address"] = orig
        return r

    for e in events:
        kind = e["kind"]
        detail = json.loads(e["detail"]) if e["detail"] else {}
        if kind == "connect":
            origin = "smtpd"
            summary["has_start"] = 1
            summary["client"] = detail.get("client")
            summary["sasl_username"] = detail.get("sasl_username")
        elif kind == "pickup":
            origin = "pickup"
            summary["has_start"] = 1
            sender_sources.setdefault("pickup", detail.get("from", ""))
            summary["orig_queue_id"] = detail.get("orig_id")
        elif kind == "cleanup":
            queued_seen = True
            if detail.get("message_id") is not None:
                summary["message_id"] = detail["message_id"]
        elif kind == "header":
            if detail.get("name", "").lower() == "subject" and summary["subject"] is None:
                summary["subject"] = detail.get("value")
        elif kind == "queued":
            summary["has_qmgr"] = 1
            summary["active_count"] += 1
            sender_sources["qmgr"] = detail.get("from", "")
            summary["size"] = detail.get("size")
            summary["nrcpt"] = detail.get("nrcpt")
        elif kind == "delivery":
            r = rcpt(e["recipient"] or "", detail.get("orig_to"))
            mapped = DELIVERY_STATUS_MAP.get((e["status"] or "").lower(), "unknown")
            r["attempts"] += 1
            r["first_attempt_ts"] = r["first_attempt_ts"] or e["ts"]
            r["last_attempt_ts"] = e["ts"]
            if mapped == "deferred":
                r["deferrals"] += 1
            if r["status"] in FINAL_STATES and mapped == "deferred":
                pass  # never downgrade a final outcome
            else:
                r["status"] = mapped
                if mapped in FINAL_STATES:
                    r["final_ts"] = e["ts"]
            r.update(dsn=e["dsn"], relay=e["relay"], response=e["response"], delay=e["delay"], delays=e["delays"])
            summary["last_dsn"], summary["last_response"] = e["dsn"], e["response"]
        elif kind == "expired":
            expired_ts = e["ts"]
            sender_sources.setdefault("expired", detail.get("from", ""))
            for r in recipients.values():
                if r["status"] not in FINAL_STATES:
                    r["status"] = "expired"
                    r["final_ts"] = e["ts"]
        elif kind in ("reject", "noqueue_reject"):
            rejected = True
            if detail.get("from") is not None:
                sender_sources.setdefault("reject", detail["from"])
            if e["recipient"]:
                r = rcpt(e["recipient"])
                r.update(status="rejected", final_ts=e["ts"], dsn=e["dsn"], response=e["response"])
            summary["last_dsn"], summary["last_response"] = e["dsn"], e["response"]
            if kind == "noqueue_reject":
                summary["has_start"] = 1
        elif kind in ("discard", "noqueue_discard"):
            discarded = True
            summary["last_response"] = e["response"]
        elif kind in ("hold", "noqueue_hold"):
            on_hold = True
        elif kind == "release":
            on_hold = False
        elif kind == "notification":
            summary["notification_qid"] = detail.get("child")
        elif kind in CLOSE_KINDS:
            closed_ts = max(closed_ts or 0, e["ts"])

    for source in ("qmgr", "pickup", "expired", "reject"):
        if source in sender_sources:
            summary["sender"] = sender_sources[source]
            break

    if closed_ts is not None:
        for r in recipients.values():
            if r["status"] not in FINAL_STATES:
                r["status"] = "removed"
                r["final_ts"] = closed_ts

    status = _message_status(
        list(recipients.values()), nrcpt=summary["nrcpt"], closed=closed_ts is not None,
        expired=expired_ts is not None, rejected=rejected, discarded=discarded, on_hold=on_hold,
        has_qmgr=bool(summary["has_qmgr"]), queued_seen=queued_seen or bool(summary["has_start"]),
    )

    conn.execute(
        "UPDATE messages SET sender = ?, message_id = ?, subject = ?, size = ?, nrcpt = ?, client = ?,"
        " sasl_username = ?, origin = ?, orig_queue_id = ?, notification_qid = ?, status = ?,"
        " has_start = ?, has_qmgr = ?, closed_ts = ?, active_count = ?, event_count = ?,"
        " last_dsn = ?, last_response = ?, first_ts = coalesce(?, first_ts), last_ts = coalesce(?, last_ts)"
        " WHERE id = ?",
        (
            summary["sender"], summary["message_id"], summary["subject"], summary["size"], summary["nrcpt"],
            summary["client"], summary["sasl_username"], origin, summary["orig_queue_id"],
            summary["notification_qid"], status, summary["has_start"], summary["has_qmgr"], closed_ts,
            summary["active_count"], len(events), summary["last_dsn"], summary["last_response"],
            first_ts, last_ts, message_id,
        ),
    )
    conn.execute("DELETE FROM recipients WHERE message_id = ?", (message_id,))
    conn.executemany(
        "INSERT INTO recipients(message_id, address, orig_address, domain, status, dsn, relay, response, delay,"
        " delays, attempts, deferrals, first_attempt_ts, last_attempt_ts, final_ts)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (message_id, r["address"], r["orig_address"], r["domain"], r["status"], r["dsn"], r["relay"],
             r["response"], r["delay"], r["delays"], r["attempts"], r["deferrals"], r["first_attempt_ts"],
             r["last_attempt_ts"], r["final_ts"])
            for r in recipients.values()
        ],
    )


def _message_status(recipients: list[dict], *, nrcpt: int | None, closed: bool, expired: bool,
                     rejected: bool, discarded: bool, on_hold: bool, has_qmgr: bool, queued_seen: bool) -> str:
    """Overall message status from recipient outcomes and queue evidence.

    ``accepted`` means every known recipient was accepted by the next hop
    (``status=sent``). It is not proof of inbox placement.
    """
    if rejected:
        return "rejected"
    if discarded:
        return "discarded"
    states = [r["status"] for r in recipients]
    if not states:
        if expired:
            return "expired"
        if closed:
            return "removed"
        if on_hold:
            return "hold"
        if has_qmgr:
            return "processing"
        return "queued" if queued_seen else "unknown"
    if on_hold and not closed:
        return "hold"
    if "deferred" in states:
        return "deferred"
    pending = nrcpt is not None and len(states) < nrcpt and not closed and not expired
    accepted = states.count(ACCEPTED)
    failed = sum(1 for s in states if s in FAILED_STATES)
    if pending:
        return "processing" if failed == 0 else "partial"
    if accepted == len(states):
        return "accepted"
    if failed == len(states):
        return "expired" if all(s == "expired" for s in states) else "bounced"
    if accepted and failed:
        return "partial"
    if all(s == "removed" for s in states):
        return "removed"
    if "unknown" in states:
        return "unknown"
    return "partial" if accepted else "bounced" if failed else "unknown"
