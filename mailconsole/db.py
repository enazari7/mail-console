"""SQLite access: connection setup, explicit transactions and migrations."""

from __future__ import annotations

import contextlib
import os
import re
import sqlite3
import stat
import time
from importlib import resources
from pathlib import Path
from typing import Iterator

MIGRATION_RE = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")


def now_us() -> int:
    return time.time_ns() // 1000


def _secure_file(path: Path) -> None:
    """Restrict a database file to its owner (0600) when we own it."""
    try:
        st = path.stat()
    except FileNotFoundError:
        return
    if st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) & 0o077:
        os.chmod(path, 0o600)


def connect(db_path: Path | str, *, readonly: bool = False) -> sqlite3.Connection:
    """Open the console database with the pragmas every process relies on.

    Connections run in autocommit mode; writes go through :func:`tx`.
    """
    path = Path(db_path)
    if not readonly:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        old_umask = os.umask(0o077)
        try:
            conn = sqlite3.connect(path, isolation_level=None, timeout=15.0, check_same_thread=False)
        finally:
            os.umask(old_umask)
    else:
        uri = f"file:{path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Unicode-aware case folding for search (SQLite's lower() is ASCII-only).
    conn.create_function("mc_fold", 1, lambda v: v.casefold() if isinstance(v, str) else v, deterministic=True)
    conn.execute("PRAGMA busy_timeout = 15000")
    conn.execute("PRAGMA foreign_keys = ON")
    if not readonly:
        # auto_vacuum must be chosen before the first table exists.
        if conn.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] == 0:
            conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
        mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(mode).lower() != "wal":
            raise RuntimeError(f"could not enable WAL mode (got {mode!r})")
        conn.execute("PRAGMA synchronous = NORMAL")
        for suffix in ("", "-wal", "-shm"):
            _secure_file(Path(str(path) + suffix))
    return conn


@contextlib.contextmanager
def tx(conn: sqlite3.Connection, *, immediate: bool = True) -> Iterator[sqlite3.Connection]:
    """Run a block inside one transaction; roll back on any exception."""
    conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def available_migrations() -> list[tuple[int, str, str]]:
    found = []
    for entry in resources.files("mailconsole.migrations").iterdir():
        match = MIGRATION_RE.match(entry.name)
        if match:
            found.append((int(match.group(1)), entry.name, entry.read_text(encoding="utf-8")))
    return sorted(found)


def applied_versions(conn: sqlite3.Connection) -> set[int]:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_ts INTEGER NOT NULL)"
    )
    return {row[0] for row in conn.execute("SELECT version FROM schema_migrations")}


def migrate(conn: sqlite3.Connection) -> list[str]:
    """Apply pending migrations, each atomically. Returns the names applied."""
    done = applied_versions(conn)
    applied = []
    for version, name, sql in available_migrations():
        if version in done:
            continue
        script = (
            "BEGIN IMMEDIATE;\n"
            f"{sql}\n"
            f"INSERT INTO schema_migrations(version, name, applied_ts) VALUES ({version}, '{name}', {now_us()});\n"
            "COMMIT;"
        )
        try:
            conn.executescript(script)
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        applied.append(name)
        post = POST_MIGRATION.get(version)
        if post:
            post(conn)
    if 2 in applied_versions(conn):
        # Re-runnable completion of the search index: covers a post-migration
        # step that was interrupted after its schema change was committed.
        from .search import fill_missing
        fill_missing(conn)
    return applied


def _rebuild_search(conn: sqlite3.Connection) -> None:
    from .search import rebuild
    rebuild(conn)


# Python steps that run once, right after the migration of the same version.
POST_MIGRATION = {2: _rebuild_search}


def pending_migrations(conn: sqlite3.Connection) -> list[str]:
    done = applied_versions(conn)
    return [name for version, name, _ in available_migrations() if version not in done]


def get_setting(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings(key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def get_state(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM collector_state WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_state(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO collector_state(key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
