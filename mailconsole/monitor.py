"""Read-only health checks: systemd unit state and the Postfix queue.

Only non-mutating commands are executed:

* ``systemctl show --property=... <unit>`` (no start/stop/restart ever)
* ``postqueue -j`` (lists the queue; never ``-f``/``-s``/``-i``)

Results are written to the console database by the collector so that web
requests never spawn processes.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
from collections import Counter
from dataclasses import dataclass

from .db import now_us

SHOW_PROPERTIES = "Id,LoadState,ActiveState,SubState,ActiveEnterTimestamp,MainPID,NRestarts,Result"
MAX_QUEUE_ENTRIES = 200


def _run(cmd: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


@dataclass
class UnitStatus:
    label: str
    unit: str
    ok: bool
    load_state: str | None = None
    active_state: str | None = None
    sub_state: str | None = None
    since: str | None = None
    main_pid: int | None = None
    restarts: int | None = None
    error: str | None = None


def parse_systemctl_show(text: str) -> dict[str, str]:
    props = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            props[key.strip()] = value.strip()
    return props


def check_unit(systemctl: str, label: str, unit: str) -> UnitStatus:
    try:
        proc = _run([systemctl, "show", f"--property={SHOW_PROPERTIES}", "--", unit])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return UnitStatus(label, unit, ok=False, error=f"systemctl unavailable: {exc.__class__.__name__}")
    if proc.returncode != 0:
        return UnitStatus(label, unit, ok=False, error=(proc.stderr or "systemctl failed").strip()[:300])
    props = parse_systemctl_show(proc.stdout)
    load, active = props.get("LoadState"), props.get("ActiveState")
    def _int(v):
        try:
            return int(v) if v not in (None, "", "[not set]") else None
        except ValueError:
            return None
    error = None
    if load == "not-found":
        error = "unit not found (check MC_MONITOR_UNITS)"
    return UnitStatus(
        label=label, unit=unit, ok=(load == "loaded" and active == "active"), load_state=load,
        active_state=active, sub_state=props.get("SubState"), since=props.get("ActiveEnterTimestamp") or None,
        main_pid=_int(props.get("MainPID")), restarts=_int(props.get("NRestarts")), error=error,
    )


@dataclass
class QueueSnapshot:
    ok: bool
    error: str | None
    total: int | None
    by_queue: dict[str, int]
    oldest_arrival_ts: int | None
    entries: list[dict]


def parse_postqueue_json(text: str, max_entries: int = MAX_QUEUE_ENTRIES) -> QueueSnapshot:
    """Parse ``postqueue -j`` output (one JSON object per line)."""
    by_queue: Counter[str] = Counter()
    entries = []
    oldest = None
    total = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        total += 1
        queue = str(item.get("queue_name", "unknown"))
        by_queue[queue] += 1
        arrival = item.get("arrival_time")
        if isinstance(arrival, (int, float)):
            arrival_us = int(arrival) * 1_000_000
            oldest = arrival_us if oldest is None else min(oldest, arrival_us)
        else:
            arrival_us = None
        if len(entries) < max_entries:
            recipients = []
            for r in item.get("recipients", [])[:20]:
                recipients.append({"address": r.get("address"), "reason": (r.get("delay_reason") or "")[:500]})
            entries.append({
                "queue_id": item.get("queue_id"), "queue": queue, "arrival_ts": arrival_us,
                "size": item.get("message_size"), "sender": item.get("sender"),
                "forced_expire": bool(item.get("forced_expire")), "recipients": recipients,
            })
    entries.sort(key=lambda e: e["arrival_ts"] or 0)
    return QueueSnapshot(True, None, total, dict(by_queue), oldest, entries)


def check_queue(postqueue: str) -> QueueSnapshot:
    try:
        proc = _run([postqueue, "-j"], timeout=20.0)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return QueueSnapshot(False, f"postqueue unavailable: {exc.__class__.__name__}", None, {}, None, [])
    if proc.returncode != 0:
        return QueueSnapshot(False, (proc.stderr or "postqueue failed").strip()[:300], None, {}, None, [])
    return parse_postqueue_json(proc.stdout)


def record_units(conn: sqlite3.Connection, statuses: list[UnitStatus]) -> None:
    ts = now_us()
    for s in statuses:
        conn.execute(
            "INSERT INTO service_status(unit, label, checked_ts, ok, load_state, active_state, sub_state, since,"
            " main_pid, restarts, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(unit) DO UPDATE SET label = excluded.label, checked_ts = excluded.checked_ts,"
            " ok = excluded.ok, load_state = excluded.load_state, active_state = excluded.active_state,"
            " sub_state = excluded.sub_state, since = excluded.since, main_pid = excluded.main_pid,"
            " restarts = excluded.restarts, error = excluded.error",
            (s.unit, s.label, ts, int(s.ok), s.load_state, s.active_state, s.sub_state, s.since, s.main_pid,
             s.restarts, s.error),
        )
    units = [s.unit for s in statuses]
    if units:
        conn.execute(f"DELETE FROM service_status WHERE unit NOT IN ({','.join('?' * len(units))})", units)


def record_queue(conn: sqlite3.Connection, snap: QueueSnapshot) -> None:
    conn.execute(
        "INSERT INTO queue_snapshots(ts, ok, error, total, by_queue, oldest_arrival_ts, entries)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (now_us(), int(snap.ok), snap.error, snap.total, json.dumps(snap.by_queue), snap.oldest_arrival_ts,
         json.dumps(snap.entries, separators=(",", ":"))),
    )
    # Only the latest snapshot keeps its entry list; older rows keep counts for the chart.
    conn.execute(
        "UPDATE queue_snapshots SET entries = NULL WHERE entries IS NOT NULL"
        " AND id < (SELECT max(id) FROM queue_snapshots)"
    )
