"""Full-text search documents (SQLite FTS5, trigram tokenizer).

The ``message_search`` table holds one document per message. Search uses
``MATCH`` with a quoted phrase, which the trigram index answers without
scanning; terms shorter than three characters cannot use the trigram index
and are restricted to exact matches by the caller.
"""

from __future__ import annotations

import sqlite3

MIN_SUBSTRING = 3
MAX_RESPONSE_CHARS = 2000  # stored responses are capped at 2,000 characters


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


def _chunks(conn: sqlite3.Connection, sql: str, chunk: int):
    last = 0
    while True:
        ids = [r[0] for r in conn.execute(sql, (last, chunk))]
        if not ids:
            return
        yield ids
        last = ids[-1]


def rebuild(conn: sqlite3.Connection, chunk: int = 2000) -> int:
    """Rewrite every search document in place, in bounded transactions.

    The index is never emptied first, so search keeps working (with at most
    one stale document per message) while a rebuild runs.
    """
    from .db import tx
    done = 0
    for ids in _chunks(conn, "SELECT id FROM messages WHERE id > ? ORDER BY id LIMIT ?", chunk):
        with tx(conn):
            for message_id in ids:
                update(conn, message_id)
        done += len(ids)
    with tx(conn):
        conn.execute("DELETE FROM message_search WHERE rowid NOT IN (SELECT id FROM messages)")
    return done


def fill_missing(conn: sqlite3.Connection, chunk: int = 2000) -> int:
    """Index messages that have no search document yet (e.g. after an interrupted rebuild)."""
    from .db import tx
    done = 0
    sql = ("SELECT id FROM messages WHERE id > ? AND id NOT IN (SELECT rowid FROM message_search)"
           " ORDER BY id LIMIT ?")
    for ids in _chunks(conn, sql, chunk):
        with tx(conn):
            for message_id in ids:
                update(conn, message_id)
        done += len(ids)
    return done


def missing_documents(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT count(*) FROM messages WHERE id NOT IN (SELECT rowid FROM message_search)"
                        ).fetchone()[0]


def fold(text: str | None) -> str:
    """Unicode case folding used by both the SQL row check and the search term."""
    return text.casefold() if text else ""
