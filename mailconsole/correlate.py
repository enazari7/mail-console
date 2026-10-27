"""Store classified log records and correlate them into messages.

Design:

* ``events`` is the source of truth. Every stored event carries a hash of
  its log line, so re-reading a line is a no-op (idempotent ingestion).
* A *message* is one lifetime of a Postfix queue file. Short queue IDs are
  reused by Postfix, so a queue ID alone does not identify a message. After
  each batch, all events of every touched queue ID are split into lifetimes
  by :func:`segment` using only the events themselves, so the grouping does
  not depend on the order in which log lines were ingested.
* Message and recipient state is *derived*: every touched message is then
  recomputed from its events. Duplicate or late input is therefore harmless.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Iterable

from . import search
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
    queue_ids: set[str] = field(default_factory=set)

    def merge(self, other: "IngestStats") -> None:
        self.lines += other.lines
        self.events += other.events
        self.duplicates += other.duplicates
        self.ops += other.ops
        self.dropped += other.dropped
        self.messages_touched |= other.messages_touched
        self.queue_ids |= other.queue_ids


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
        self._batch_counts: dict = {}
        self._dropped: list[tuple[str, str, int]] = []
        touched_qids: set[tuple[str, str]] = set()
        for item in items:
            stats.lines += 1
            if item.ops is not None:
                self._store_ops(item, stats)
            elif item.event is not None:
                key = self._store_event(item, stats)
                if key is not None:
                    touched_qids.add(key)
        for qid, host in sorted(touched_qids):
            stats.messages_touched |= self._resegment(qid, host)
            stats.queue_ids.add(qid)
        for qid, host, ts in self._dropped:
            self.conn.execute(
                "UPDATE messages SET events_truncated = 1 WHERE id = (SELECT id FROM messages WHERE queue_id = ?"
                " AND host IS ? AND first_ts <= ? ORDER BY first_ts DESC LIMIT 1)", (qid, host, ts))
        live = {r[0] for r in self.conn.execute(
            f"SELECT id FROM messages WHERE id IN ({','.join('?' * len(stats.messages_touched))})",
            sorted(stats.messages_touched))} if stats.messages_touched else set()
        stats.messages_touched = live
        for message_id in sorted(live):
            recompute_message(self.conn, message_id)
        self._link_notifications(live)
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

    def _store_ops(self, item: Classified, stats: IngestStats) -> None:
        rec = item.record
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO ops_events(ts, host, program, pid, level, message, line_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (rec.ts, rec.host, rec.program, rec.pid, item.ops.level, redact(item.ops.message)[:4000],
             rec.line_hash),
        )
        if cur.rowcount:
            stats.ops += 1
        else:
            stats.duplicates += 1

    def _store_event(self, item: Classified, stats: IngestStats) -> tuple[str, str] | None:
        """Insert an event. Queue-ID events get their message in :meth:`_resegment`."""
        rec, ev = item.record, item.event
        line_hash = rec.line_hash
        if self.conn.execute("SELECT 1 FROM events WHERE line_hash = ?", (line_hash,)).fetchone():
            stats.duplicates += 1
            return None

        message_id = None
        if ev.queue_id is None:
            message_id = self._new_message(None, rec.host, rec.ts, origin="noqueue")
            stats.messages_touched.add(message_id)
        else:
            # Per-message cap on retry noise, checked against the message the
            # event most likely belongs to (final outcomes are never dropped).
            droppable = ev.kind in DROPPABLE or (ev.kind == "delivery" and ev.status == "deferred")
            if droppable:
                row = self.conn.execute(
                    "SELECT id, event_count FROM messages WHERE queue_id = ? AND host IS ? AND first_ts <= ?"
                    " ORDER BY first_ts DESC LIMIT 1", (ev.queue_id, rec.host, rec.ts)).fetchone()
                key = row["id"] if row is not None else (ev.queue_id, rec.host)
                count = (row["event_count"] if row is not None else 0) + self._batch_counts.get(key, 0)
                if count >= self.max_events:
                    self._dropped.append((ev.queue_id, rec.host, rec.ts))
                    stats.dropped += 1
                    return None
                self._batch_counts[key] = self._batch_counts.get(key, 0) + 1

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
        stats.events += 1
        if ev.kind == "archive_delivery" and ev.status != "sent":
            # The archive copy is deferred or failed (e.g. low disk space):
            # surface it as an operational problem; real recipients are unaffected.
            self.conn.execute(
                "INSERT OR IGNORE INTO ops_events(ts, host, program, pid, level, message, line_hash)"
                " VALUES (?, ?, ?, ?, 'error', ?, ?)",
                (rec.ts, rec.host, rec.program, rec.pid,
                 f"Mail Console archive copy for {ev.queue_id} {ev.status}: {redact(ev.response or '')}"[:4000],
                 line_hash[:-1] + b"A"))
        return (ev.queue_id, rec.host) if ev.queue_id is not None else None

    def _new_message(self, queue_id: str | None, host: str, ts: int, origin: str = "unknown") -> int:
        cur = self.conn.execute(
            "INSERT INTO messages(queue_id, host, first_ts, last_ts, origin, status) VALUES (?, ?, ?, ?, ?, 'unknown')",
            (queue_id, host, ts, ts, origin),
        )
        return cur.lastrowid

    def _resegment(self, qid: str, host: str) -> set[int]:
        """Regroup all events of one queue ID into messages; return affected message ids.

        Existing message ids are kept where a lifetime keeps most of its events,
        so links to messages stay stable as more evidence arrives.
        """
        rows = self.conn.execute(
            "SELECT id, ts, kind, message_id FROM events WHERE queue_id = ? AND host IS ?",
            (qid, host)).fetchall()
        segments = segment([dict(r) for r in rows], self.gap_us)
        before = {r["message_id"] for r in rows if r["message_id"] is not None}
        used: set[int] = set()
        for seg in segments:
            if all(e["kind"] in ATTACH_ONLY for e in seg):
                # Milter/DKIM notes with no Postfix lifetime around them: keep
                # them unattached rather than inventing a message.
                target = None
            else:
                votes: dict[int, int] = {}
                for e in seg:
                    if e["message_id"] is not None and e["message_id"] not in used:
                        votes[e["message_id"]] = votes.get(e["message_id"], 0) + 1
                if votes:
                    target = max(votes, key=lambda mid: (votes[mid], -mid))
                else:
                    target = self._new_message(qid, host, seg[0]["ts"])
                used.add(target)
            changed = [e["id"] for e in seg if e["message_id"] != target]
            for i in range(0, len(changed), 500):
                chunk = changed[i:i + 500]
                self.conn.execute(f"UPDATE events SET message_id = ? WHERE id IN ({','.join('?' * len(chunk))})",
                                  [target, *chunk])
        orphaned = before - used
        if orphaned:
            marks = ",".join("?" * len(orphaned))
            self.conn.execute(f"DELETE FROM messages WHERE id IN ({marks})", sorted(orphaned))
        return used | orphaned


ATTACH_ONLY = {"milter_info"}
_KIND_ORDER = {"connect": 0, "pickup": 0, "removed": 9, "requeued": 9}


def segment(events: list[dict], gap_us: int) -> list[list[dict]]:
    """Split one queue ID's events into queue-file lifetimes.

    Events are taken in time order (starts first and closes last within the
    same timestamp, which matters for second-resolution syslog). A new
    lifetime begins when:

    1. the previous one was closed (``removed`` or ``requeued``);
    2. a start record (smtpd ``client=``, pickup ``uid=``) arrives and the
       current lifetime already has one, or already has events more than
       ``SKEW_US`` older (a start is always the first record of a lifetime);
    3. the queue ID was silent for longer than ``gap_us``.

    The result depends only on the set of events, not on ingestion order.
    """
    ordered = sorted(events, key=lambda e: (e["ts"], _KIND_ORDER.get(e["kind"], 5), e["id"]))
    segments: list[list[dict]] = []
    current: list[dict] = []
    has_start = closed = False
    for e in ordered:
        kind = e["kind"]
        if current:
            split = (
                closed
                or e["ts"] - current[-1]["ts"] > gap_us
                or (kind in START_KINDS and (has_start or e["ts"] - current[0]["ts"] > SKEW_US))
            )
            if split:
                segments.append(current)
                current, has_start, closed = [], False, False
        current.append(e)
        has_start |= kind in START_KINDS
        closed |= kind in CLOSE_KINDS
    if current:
        segments.append(current)
    return segments


def _detail(ev) -> dict:
    detail = {k: v for k, v in ev.detail.items() if v not in (None, "", {})}
    if ev.orig_recipient:
        detail["orig_to"] = ev.orig_recipient
    if "text" in detail:
        detail["text"] = redact(detail["text"])
    return detail


# --- derived state ---------------------------------------------------------

def recompute_message(conn: sqlite3.Connection, message_id: int) -> None:
    """Rebuild a message's summary, recipient rows and search document from its events."""
    _recompute(conn, message_id)
    search.update(conn, message_id)


def _recompute(conn: sqlite3.Connection, message_id: int) -> None:
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
        "archive_status": None, "archive_ts": None, "archive_response": None,
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
        elif kind == "archive_delivery":
            # The Mail Console archive copy: tracked separately, never a recipient.
            summary["archive_status"], summary["archive_ts"], summary["archive_response"] = (
                e["status"], e["ts"], e["response"])
        elif kind == "expired":
            expired_ts = e["ts"]
            sender_sources.setdefault("expired", detail.get("from", ""))
            for r in recipients.values():
                if r["status"] not in FINAL_STATES:
                    r["status"] = "expired"
                    r["final_ts"] = e["ts"]
        elif kind in ("reject", "noqueue_reject"):
            # A reject at RCPT stage refuses one recipient; the message may still
            # be delivered to the others. Any other stage refuses the message.
            if not (e["recipient"] and detail.get("stage") == "RCPT"):
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

    if summary["archive_status"] is not None and summary["nrcpt"]:
        summary["nrcpt"] -= 1   # Postfix's nrcpt includes the archive copy
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
        " last_dsn = ?, last_response = ?, first_ts = coalesce(?, first_ts), last_ts = coalesce(?, last_ts),"
        " archive_status = ?, archive_ts = ?, archive_response = ?"
        " WHERE id = ?",
        (
            summary["sender"], summary["message_id"], summary["subject"], summary["size"], summary["nrcpt"],
            summary["client"], summary["sasl_username"], origin, summary["orig_queue_id"],
            summary["notification_qid"], status, summary["has_start"], summary["has_qmgr"], closed_ts,
            summary["active_count"], len(events), summary["last_dsn"], summary["last_response"],
            first_ts, last_ts, summary["archive_status"], summary["archive_ts"], summary["archive_response"],
            message_id,
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
    # nrcpt counts recipients the queue manager will deliver; RCPT-stage
    # rejects are not among them.
    queued_states = [s for s in states if s != "rejected"]
    pending = nrcpt is not None and len(queued_states) < nrcpt and not closed and not expired
    accepted = states.count(ACCEPTED)
    failed = sum(1 for s in states if s in FAILED_STATES)
    if pending:
        return "processing" if failed == 0 else "partial"
    if accepted == len(states):
        return "accepted"
    if failed == len(states):
        if all(s == "expired" for s in states):
            return "expired"
        return "rejected" if all(s == "rejected" for s in states) else "bounced"
    if accepted and failed:
        return "partial"
    if all(s == "removed" for s in states):
        return "removed"
    if "unknown" in states:
        return "unknown"
    return "partial" if accepted else "bounced" if failed else "unknown"
