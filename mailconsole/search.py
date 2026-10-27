"""Full-text search documents (SQLite FTS5, trigram tokenizer).

The ``message_search`` table holds one document per message. Search uses
``MATCH`` with a quoted phrase, which the trigram index answers without
scanning; terms shorter than three characters cannot use the trigram index
and are restricted to exact matches by the caller.
"""

from __future__ import annotations

import sqlite3

MIN_SUBSTRING = 3
MAX_RESPONSE_CHARS = 300


def phrase(term: str) -> str:
    """Quote a user term as an FTS5 phrase; no FTS operators survive quoting."""
    return '"' + term.replace('"', '""') + '"'


def build_doc(conn: sqlite3.Connection, message_id: int) -> str | None:
    m = conn.execute(
        "SELECT queue_id, sender, message_id, subject, sasl_username, last_response FROM messages WHERE id = ?",
        (message_id,)).fetchone()
    if m is None:
        return None
    parts = [m["queue_id"], m["sender"], m["message_id"], m["subject"], m["sasl_username"]]
    for r in conn.execute("SELECT address, orig_address, domain, status, response FROM recipients"
                          " WHERE message_id = ? ORDER BY id", (message_id,)):
        parts += [r["address"], r["orig_address"], r["domain"]]
        if r["status"] != "accepted" and r["response"]:
            parts.append(r["response"][:MAX_RESPONSE_CHARS])
    if m["last_response"]:
        parts.append(m["last_response"][:MAX_RESPONSE_CHARS])
    return " ".join(p for p in parts if p)


def update(conn: sqlite3.Connection, message_id: int) -> None:
    conn.execute("DELETE FROM message_search WHERE rowid = ?", (message_id,))
    doc = build_doc(conn, message_id)
    if doc:
        conn.execute("INSERT INTO message_search(rowid, doc) VALUES (?, ?)", (message_id, doc))


def rebuild(conn: sqlite3.Connection, chunk: int = 2000) -> int:
    """(Re)build every search document, in bounded transactions."""
    from .db import tx
    with tx(conn):
        conn.execute("DELETE FROM message_search")
    done, last = 0, 0
    while True:
        ids = [r[0] for r in conn.execute("SELECT id FROM messages WHERE id > ? ORDER BY id LIMIT ?", (last, chunk))]
        if not ids:
            return done
        with tx(conn):
            for message_id in ids:
                update(conn, message_id)
        done += len(ids)
        last = ids[-1]


def missing_documents(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT count(*) FROM messages WHERE id NOT IN (SELECT rowid FROM message_search)"
                        ).fetchone()[0]
