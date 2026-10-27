import os
import sqlite3
import stat

import pytest

from mailconsole import db as dbmod
from mailconsole.db import connect, migrate, pending_migrations

from .conftest import fixture_lines, ingest_lines, snapshot


def test_migrations_are_idempotent_and_recorded(cfg):
    conn = connect(cfg.db_path)
    assert migrate(conn) == ["0001_initial.sql", "0002_search_and_content.sql"]
    assert migrate(conn) == [] and pending_migrations(conn) == []
    assert [r[0] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")] == [1, 2]
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2  # incremental


def test_failed_migration_rolls_back(cfg, monkeypatch):
    conn = connect(cfg.db_path)
    migrate(conn)
    broken = [(99, "0099_broken.sql", "CREATE TABLE half_done (x INTEGER); THIS IS NOT SQL;")]
    monkeypatch.setattr(dbmod, "available_migrations", lambda: broken)
    with pytest.raises(sqlite3.OperationalError):
        migrate(conn)
    assert not conn.in_transaction
    assert conn.execute("SELECT count(*) FROM sqlite_master WHERE name = 'half_done'").fetchone()[0] == 0
    assert conn.execute("SELECT max(version) FROM schema_migrations").fetchone()[0] == 2


def test_history_survives_restart(cfg):
    conn = connect(cfg.db_path)
    migrate(conn)
    ingest_lines(conn, cfg, fixture_lines())
    before = snapshot(conn)
    conn.close()
    reopened = connect(cfg.db_path)
    assert snapshot(reopened) == before and len(before[0]) == 13


def test_file_permissions(cfg):
    conn = connect(cfg.db_path)
    migrate(conn)
    for suffix in ("", "-wal"):
        path = str(cfg.db_path) + suffix
        if os.path.exists(path):
            assert stat.S_IMODE(os.stat(path).st_mode) & 0o077 == 0, path


def test_cascade_delete(cfg):
    conn = connect(cfg.db_path)
    migrate(conn)
    ingest_lines(conn, cfg, fixture_lines())
    conn.execute("DELETE FROM messages")
    assert conn.execute("SELECT count(*) FROM events WHERE message_id IS NOT NULL").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM recipients").fetchone()[0] == 0


def test_reindex_command(cfg, monkeypatch, capsys):
    from mailconsole import cli
    conn = connect(cfg.db_path)
    migrate(conn)
    ingest_lines(conn, cfg, fixture_lines())
    conn.execute("DELETE FROM message_search")
    conn.close()
    assert cli.main(["reindex"]) == 0
    assert "rebuilt 13 search documents" in capsys.readouterr().out
    conn = connect(cfg.db_path)
    assert conn.execute("SELECT count(*) FROM message_search").fetchone()[0] == 13
