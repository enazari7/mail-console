import os
import sqlite3
from pathlib import Path

import pytest

from mailconsole.collector import ingest_batch, make_ingestor, classify_lines
from mailconsole.config import load_config
from mailconsole.db import connect, migrate, tx

FIXTURES = Path(__file__).parent / "fixtures"
ISO_LOG = FIXTURES / "syslog-iso.log"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    for key in list(os.environ):
        if key.startswith("MC_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("MC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("MC_LOG_PATH", str(tmp_path / "log" / "syslog"))
    monkeypatch.setenv("MC_COOKIE_SECURE", "false")
    monkeypatch.setenv("MC_POSTQUEUE", "/nonexistent/postqueue")
    monkeypatch.setenv("MC_SYSTEMCTL", "/nonexistent/systemctl")
    (tmp_path / "log").mkdir()
    return load_config()


@pytest.fixture
def db(cfg) -> sqlite3.Connection:
    conn = connect(cfg.db_path)
    migrate(conn)
    yield conn
    conn.close()


def ingest_lines(conn, cfg, lines, **ingestor_kwargs):
    from datetime import datetime, timezone
    ref = datetime(2026, 10, 27, tzinfo=timezone.utc)
    items = classify_lines(cfg, ((ln, ref) for ln in lines))
    ingestor = make_ingestor(conn, cfg)
    for key, value in ingestor_kwargs.items():
        setattr(ingestor, key, value)
    with tx(conn):
        return ingest_batch(conn, cfg, ingestor, items)


def fixture_lines() -> list[str]:
    return ISO_LOG.read_text().splitlines()


def snapshot(conn):
    """Order-independent view of derived state, for comparing ingest runs."""
    msgs = conn.execute(
        "SELECT queue_id, first_ts, last_ts, sender, message_id, status, nrcpt, origin, has_start, closed_ts,"
        " active_count, event_count FROM messages ORDER BY first_ts, queue_id").fetchall()
    rcpts = conn.execute(
        "SELECT m.queue_id, m.first_ts, r.address, r.status, r.dsn, r.attempts, r.deferrals, r.final_ts"
        " FROM recipients r JOIN messages m ON m.id = r.message_id ORDER BY m.first_ts, r.address").fetchall()
    return [tuple(r) for r in msgs], [tuple(r) for r in rcpts]
