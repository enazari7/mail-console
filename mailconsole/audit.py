"""Audit trail for access to archived message content and security events."""

from __future__ import annotations

import sqlite3

from .db import now_us, tx


def record(conn: sqlite3.Connection, *, admin_id: int | None, username: str | None, client_ip: str | None,
           action: str, target: str | None = None, detail: str | None = None) -> None:
    with tx(conn):
        conn.execute(
            "INSERT INTO audit_log(ts, admin_id, username, client_ip, action, target, detail)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (now_us(), admin_id, username, client_ip, action, target, (detail or "")[:500] or None))


def recent(conn: sqlite3.Connection, limit: int = 200, action: str = "") -> list[dict]:
    args: list = []
    where = ""
    if action:
        where = " WHERE action = ?"
        args.append(action)
    return [dict(r) for r in conn.execute(
        f"SELECT * FROM audit_log{where} ORDER BY ts DESC, id DESC LIMIT ?", args + [limit])]
