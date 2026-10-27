"""The collector daemon: ingest logs, record health snapshots, apply retention."""

from __future__ import annotations

import fcntl
import hashlib
import logging
import os
import signal
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable

from . import monitor
from .config import Config
from .correlate import IngestStats, Ingestor
from .db import connect, get_setting, get_state, now_us, pending_migrations, set_state, tx
from .parser import Classified, LogRecord, classify, parse_syslog_line
from .sources import FileSource, JournaldSource, iter_file_lines, load_checkpoint, save_checkpoint

log = logging.getLogger("mailconsole.collector")

HEARTBEAT_SECONDS = 15.0
MAINTENANCE_SECONDS = 3600.0
QUEUE_SNAPSHOT_RETENTION_DAYS = 14
DELETE_CHUNK = 500


class LockBusy(RuntimeError):
    pass


class CollectorLock:
    """Exclusive lock so only one process ingests at a time."""

    def __init__(self, path: Path):
        self.path = path
        self.fd: int | None = None

    def __enter__(self) -> "CollectorLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            self.fd = None
            raise LockBusy(f"another collector or import holds {self.path}") from None
        return self

    def __exit__(self, *exc) -> None:
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None


def require_schema(conn: sqlite3.Connection) -> None:
    pending = pending_migrations(conn)
    if pending:
        raise SystemExit(f"database schema is not up to date (pending: {', '.join(pending)}); "
                         "run 'mail-console migrate' first")


def classify_lines(cfg: Config, lines: Iterable[tuple[str, datetime]]) -> list[Classified]:
    out = []
    for line, ref in lines:
        record = parse_syslog_line(line, bsd_tz=cfg.log_timezone, reference=ref)
        if record is None:
            continue
        item = classify(record, cfg.postfix_prefixes, cfg.ops_programs)
        if item is not None:
            out.append(item)
    return out


def classify_records(cfg: Config, records: Iterable[LogRecord]) -> list[Classified]:
    out = []
    for record in records:
        item = classify(record, cfg.postfix_prefixes, cfg.ops_programs)
        if item is not None:
            out.append(item)
    return out


def note(conn: sqlite3.Connection, text: str, level: str = "warning") -> None:
    ts = now_us()
    digest = hashlib.sha256(f"{ts}\x1fnote\x1f{text}".encode()).digest()[:16]
    conn.execute(
        "INSERT OR IGNORE INTO ops_events(ts, host, program, pid, level, message, line_hash)"
        " VALUES (?, NULL, 'mail-console', ?, ?, ?, ?)",
        (ts, os.getpid(), level, text, digest),
    )


def _bump(conn: sqlite3.Connection, key: str, amount: int) -> None:
    if amount:
        set_state(conn, key, str(int(get_state(conn, key, "0")) + amount))


def make_ingestor(conn: sqlite3.Connection, cfg: Config) -> Ingestor:
    return Ingestor(conn, reuse_gap_hours=cfg.queue_reuse_gap_hours,
                    max_events_per_message=cfg.max_events_per_message, store_raw=cfg.store_raw_lines)


def ingest_batch(conn: sqlite3.Connection, cfg: Config, ingestor: Ingestor, items: list[Classified]) -> IngestStats:
    """Ingest items and update counters; caller owns the transaction."""
    stats = ingestor.ingest(items)
    _bump(conn, "events_total", stats.events)
    _bump(conn, "duplicates_total", stats.duplicates)
    if items:
        latest = max(i.record.ts for i in items)
        if latest > int(get_state(conn, "last_log_ts", "0")):
            set_state(conn, "last_log_ts", str(latest))
    return stats


def import_files(cfg: Config, paths: list[Path], *, echo: Callable[[str], None] = print) -> IngestStats:
    """Import whole log files (plain or .gz) in the given order. Idempotent."""
    total = IngestStats()
    conn = connect(cfg.db_path)
    try:
        require_schema(conn)
        with CollectorLock(cfg.data_dir / "collector.lock"):
            ingestor = make_ingestor(conn, cfg)
            for path in paths:
                file_stats = IngestStats()
                for lines, ref in iter_file_lines(path, cfg.max_line_bytes, cfg.batch_lines):
                    items = classify_lines(cfg, ((ln, ref) for ln in lines))
                    with tx(conn):
                        stats = ingest_batch(conn, cfg, ingestor, items)
                    file_stats.merge(stats)
                    file_stats.lines += len(lines) - len(items)
                echo(f"{path}: {file_stats.lines} lines, {file_stats.events} new events, "
                     f"{file_stats.duplicates} already known, {len(file_stats.messages_touched)} messages")
                total.merge(file_stats)
    finally:
        conn.close()
    return total


# --- retention -------------------------------------------------------------

def retention_days(conn: sqlite3.Connection, cfg: Config) -> int:
    try:
        return max(1, int(get_setting(conn, "retention_days", str(cfg.default_retention_days))))
    except ValueError:
        return cfg.default_retention_days


def live_db_bytes(conn: sqlite3.Connection) -> int:
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    pages = conn.execute("PRAGMA page_count").fetchone()[0]
    free = conn.execute("PRAGMA freelist_count").fetchone()[0]
    return (pages - free) * page_size


def _delete_messages_before(conn: sqlite3.Connection, cutoff_us: int) -> int:
    removed = 0
    while True:
        with tx(conn):
            ids = [r[0] for r in conn.execute(
                "SELECT id FROM messages WHERE last_ts < ? ORDER BY last_ts LIMIT ?", (cutoff_us, DELETE_CHUNK))]
            if not ids:
                return removed
            marks = ",".join("?" * len(ids))
            conn.execute(f"DELETE FROM messages WHERE id IN ({marks})", ids)
        removed += len(ids)


def apply_retention(conn: sqlite3.Connection, cfg: Config, *, now: int | None = None) -> dict:
    """Delete data older than the retention window and enforce the size cap."""
    now = now or now_us()
    days = retention_days(conn, cfg)
    cutoff = now - days * 86400 * 1_000_000
    result = {"retention_days": days, "messages": _delete_messages_before(conn, cutoff)}
    with tx(conn):
        result["ops_events"] = conn.execute("DELETE FROM ops_events WHERE ts < ?", (cutoff,)).rowcount
        # Milter/DKIM notes that never matched a Postfix message lifetime.
        conn.execute("DELETE FROM events WHERE message_id IS NULL AND ts < ?", (cutoff,))
        snap_cutoff = now - min(days, QUEUE_SNAPSHOT_RETENTION_DAYS) * 86400 * 1_000_000
        conn.execute("DELETE FROM queue_snapshots WHERE ts < ?", (snap_cutoff,))
        conn.execute("DELETE FROM sessions WHERE expires_ts < ?", (now,))
        conn.execute("DELETE FROM login_attempts WHERE success = 0 AND ts < ?", (now - 7 * 86400 * 1_000_000,))
        conn.execute("DELETE FROM login_attempts WHERE ts < ?", (now - 31 * 86400 * 1_000_000,))

    cap = cfg.max_db_mb * 1024 * 1024
    trimmed = 0
    while live_db_bytes(conn) > cap:
        oldest = conn.execute("SELECT min(last_ts), max(last_ts) FROM messages").fetchone()
        if oldest[0] is None:
            break
        # Drop the oldest ~5% of the retained time span per round.
        step = max((oldest[1] - oldest[0]) // 20, 1_000_000)
        trimmed += _delete_messages_before(conn, oldest[0] + step)
        with tx(conn):
            conn.execute("DELETE FROM ops_events WHERE ts < ?", (oldest[0] + step,))
    if trimmed:
        with tx(conn):
            note(conn, f"database size cap MC_MAX_DB_MB={cfg.max_db_mb} reached; removed {trimmed} oldest messages")
    result["size_cap_trimmed"] = trimmed
    conn.execute("PRAGMA incremental_vacuum")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    with tx(conn):
        set_state(conn, "last_maintenance_ts", str(now))
    return result


# --- daemon ----------------------------------------------------------------

def run_monitor(conn: sqlite3.Connection, cfg: Config) -> None:
    units = [monitor.check_unit(cfg.systemctl_cmd, label, unit) for label, unit in cfg.monitor_units]
    queue = monitor.check_queue(cfg.postqueue_cmd)
    with tx(conn):
        monitor.record_units(conn, units)
        monitor.record_queue(conn, queue)


class Collector:
    def __init__(self, cfg: Config, *, stop: threading.Event | None = None, enable_monitor: bool = True):
        self.cfg = cfg
        self.stop = stop or threading.Event()
        self.enable_monitor = enable_monitor
        if cfg.log_source == "journald":
            self.source = JournaldSource(cfg.journalctl_cmd, cfg.journal_units)
        else:
            self.source = FileSource(cfg.log_path, max_line_bytes=cfg.max_line_bytes)

    def step(self, conn: sqlite3.Connection, ingestor: Ingestor) -> bool:
        """Process one batch. Returns True if more data is immediately available."""
        cp = load_checkpoint(conn, self.source.name)
        batch = self.source.poll(cp, self.cfg.batch_lines)
        if batch.lines or batch.records or batch.notes or (batch.checkpoint and batch.checkpoint != cp):
            items = classify_lines(self.cfg, batch.lines) + classify_records(self.cfg, batch.records)
            with tx(conn):
                ingest_batch(conn, self.cfg, ingestor, items)
                _bump(conn, "lines_total", len(batch.lines) + len(batch.records))
                for text in batch.notes:
                    log.warning(text)
                    note(conn, text, "warning" if "missing" in text or "truncated" in text else "info")
                if batch.checkpoint is not None:
                    save_checkpoint(conn, self.source.name, batch.checkpoint)
                set_state(conn, "last_batch_ts", str(now_us()))
        return batch.more

    def run(self) -> None:
        cfg = self.cfg
        with CollectorLock(cfg.data_dir / "collector.lock"):
            conn = connect(cfg.db_path)
            require_schema(conn)
            ingestor = make_ingestor(conn, cfg)
            with tx(conn):
                set_state(conn, "collector_started_ts", str(now_us()))
                set_state(conn, "collector_source", self.source.name)
            log.info("collector started: source=%s db=%s", self.source.name, cfg.db_path)
            next_heartbeat = next_monitor = 0.0
            next_maintenance = time.monotonic() + 60.0
            while not self.stop.is_set():
                more = False
                try:
                    more = self.step(conn, ingestor)
                    now = time.monotonic()
                    if now >= next_heartbeat:
                        with tx(conn):
                            set_state(conn, "collector_heartbeat_ts", str(now_us()))
                        next_heartbeat = now + HEARTBEAT_SECONDS
                    if self.enable_monitor and now >= next_monitor:
                        run_monitor(conn, cfg)
                        next_monitor = now + cfg.monitor_interval
                    if now >= next_maintenance:
                        result = apply_retention(conn, cfg)
                        log.info("maintenance: %s", result)
                        next_maintenance = now + MAINTENANCE_SECONDS
                except sqlite3.OperationalError as exc:
                    log.error("database error: %s", exc)
                    more = False
                    self.stop.wait(5.0)
                except (OSError, EOFError) as exc:
                    # E.g. a rotated file deleted or still being compressed by
                    # logrotate. The checkpoint is unchanged; retry shortly.
                    log.warning("log read error, retrying: %s", exc)
                    more = False
                    self.stop.wait(5.0)
                if not more:
                    self.stop.wait(cfg.poll_interval)
            conn.close()
            log.info("collector stopped")


def main(cfg: Config) -> None:
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    Collector(cfg, stop=stop).run()
