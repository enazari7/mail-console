"""Read-only log sources with durable, incremental checkpoints.

``FileSource`` tails a syslog file (default ``/var/log/syslog``) and survives
logrotate (rename + create, with or without ``delaycompress``), copytruncate
and collector restarts. ``JournaldSource`` reads ``journalctl --output=json``
after a stored cursor. Neither source writes to anything except the console
database.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import sqlite3
import subprocess
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterator

from .db import now_us
from .parser import LogRecord

FP_LEN = 256                   # bytes of file head used to recognise a file
ROTATE_SETTLE_SECONDS = 5.0    # wait this long for writers to leave a rotated file


@dataclass(frozen=True)
class Checkpoint:
    path: str
    dev: int
    inode: int
    offset: int
    fingerprint: bytes
    fingerprint_len: int
    cursor: str | None = None


@dataclass
class Batch:
    lines: list[tuple[str, datetime]]        # (line, reference time for BSD year inference)
    records: list[LogRecord]                 # pre-parsed records (journald)
    checkpoint: Checkpoint | None
    notes: list[str]                         # operational notes (gaps, rotations)
    more: bool                               # more data is immediately available


def load_checkpoint(conn: sqlite3.Connection, source: str) -> Checkpoint | None:
    row = conn.execute("SELECT * FROM checkpoints WHERE source = ?", (source,)).fetchone()
    if row is None:
        return None
    return Checkpoint(path=row["path"], dev=row["dev"] or 0, inode=row["inode"] or 0, offset=row["offset"] or 0,
                      fingerprint=row["fingerprint"] or b"", fingerprint_len=row["fingerprint_len"] or 0,
                      cursor=row["cursor"])


def save_checkpoint(conn: sqlite3.Connection, source: str, cp: Checkpoint) -> None:
    conn.execute(
        "INSERT INTO checkpoints(source, path, dev, inode, offset, fingerprint, fingerprint_len, cursor, updated_ts)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(source) DO UPDATE SET path = excluded.path,"
        " dev = excluded.dev, inode = excluded.inode, offset = excluded.offset, fingerprint = excluded.fingerprint,"
        " fingerprint_len = excluded.fingerprint_len, cursor = excluded.cursor, updated_ts = excluded.updated_ts",
        (source, cp.path, cp.dev, cp.inode, cp.offset, cp.fingerprint, cp.fingerprint_len, cp.cursor, now_us()),
    )


def _open(path: Path) -> BinaryIO:
    if path.suffix == ".gz":
        return gzip.open(path, "rb")
    return open(path, "rb")


def _head(path: Path, length: int) -> bytes:
    try:
        with _open(path) as fh:
            return fh.read(length)
    except (OSError, EOFError):
        return b""


def _decode(raw: bytes) -> str:
    return raw.rstrip(b"\r\n").decode("utf-8", errors="replace")


def read_lines(fh: BinaryIO, max_lines: int, max_line_bytes: int, *, take_partial: bool) -> tuple[list[str], int, bool]:
    """Read up to ``max_lines`` complete lines from the current position.

    Returns (lines, bytes_consumed, more). An incomplete trailing line is left
    unread unless ``take_partial``. Overlong lines are truncated, not split.
    """
    lines: list[str] = []
    consumed = 0
    while len(lines) < max_lines:
        chunk = fh.readline(max_line_bytes + 1)
        if not chunk:
            return lines, consumed, False
        size = len(chunk)
        if not chunk.endswith(b"\n") and size > max_line_bytes:
            # Overlong line: keep the head, skip to the end of the line.
            while True:
                rest = fh.readline(65536)
                if not rest:
                    if not take_partial:
                        return lines, consumed, False
                    break
                size += len(rest)
                if rest.endswith(b"\n"):
                    break
            lines.append(_decode(chunk[:max_line_bytes]))
            consumed += size
            continue
        if not chunk.endswith(b"\n") and not take_partial:
            return lines, consumed, False
        lines.append(_decode(chunk))
        consumed += size
    return lines, consumed, True


def rotated_siblings(path: Path) -> list[Path]:
    """Rotated copies of ``path``, oldest first (syslog.7.gz ... syslog.1)."""
    pattern = re.compile(rf"^{re.escape(path.name)}\.(\d+)(\.gz)?$")
    found = []
    try:
        entries = list(path.parent.iterdir())
    except OSError:
        return []
    for entry in entries:
        m = pattern.match(entry.name)
        if m and entry.is_file():
            found.append((int(m.group(1)), entry))
    return [p for _, p in sorted(found, key=lambda x: -x[0])]


class FileSource:
    def __init__(self, path: Path, *, max_line_bytes: int = 16384):
        self.path = Path(path)
        self.max_line_bytes = max_line_bytes
        self.name = f"file:{self.path}"

    def _identity(self, st: os.stat_result, offset: int = 0) -> Checkpoint:
        fp = _head(self.path, FP_LEN)
        return Checkpoint(path=str(self.path), dev=st.st_dev, inode=st.st_ino, offset=offset,
                          fingerprint=fp, fingerprint_len=len(fp))

    def _find_rotated(self, cp: Checkpoint) -> Path | None:
        """Locate the file a checkpoint refers to after rotation."""
        for candidate in [self.path.with_name(self.path.name + s) for s in (".1", ".0", "-1")] + rotated_siblings(self.path):
            try:
                st = candidate.stat()
            except OSError:
                continue
            same_inode = candidate.suffix != ".gz" and (st.st_dev, st.st_ino) == (cp.dev, cp.inode)
            if not same_inode and cp.fingerprint_len < 64:
                continue  # a copy (copytruncate or .gz) is only recognisable by enough content
            if cp.fingerprint_len and _head(candidate, cp.fingerprint_len) != cp.fingerprint:
                continue
            return candidate
        return None

    def _next_newer(self, rotated: Path) -> Path | None:
        siblings = rotated_siblings(self.path)  # oldest first
        if rotated not in siblings:
            return None
        index = siblings.index(rotated)
        return siblings[index + 1] if index + 1 < len(siblings) else None

    def _identity_of(self, path: Path) -> Checkpoint:
        st = path.stat()
        fp = _head(path, FP_LEN)
        return Checkpoint(path=str(self.path), dev=st.st_dev, inode=st.st_ino, offset=0,
                          fingerprint=fp, fingerprint_len=len(fp))

    def _same_file(self, cp: Checkpoint, st: os.stat_result) -> bool:
        if (st.st_dev, st.st_ino) != (cp.dev, cp.inode):
            return False
        if cp.fingerprint_len and _head(self.path, cp.fingerprint_len) != cp.fingerprint:
            return False  # inode reused by a new file
        return True

    def _read(self, path: Path, offset: int, max_lines: int, take_partial: bool) -> tuple[list[str], int, bool]:
        with _open(path) as fh:
            if path.suffix == ".gz":
                remaining = offset
                while remaining > 0:
                    skipped = len(fh.read(min(remaining, 1 << 20)))
                    if not skipped:
                        break
                    remaining -= skipped
            else:
                fh.seek(offset)
            return read_lines(fh, max_lines, self.max_line_bytes, take_partial=take_partial)

    def poll(self, cp: Checkpoint | None, max_lines: int) -> Batch:
        notes: list[str] = []
        try:
            st = self.path.stat()
        except FileNotFoundError:
            st = None

        if cp is None:
            if st is None:
                return Batch([], [], None, [f"log file {self.path} does not exist yet"], False)
            cp = self._identity(st)

        if st is None or not self._same_file(cp, st):
            old = self._find_rotated(cp)
            if old is not None:
                settled = st is not None and (st.st_size > 0 or time.time() - old.stat().st_mtime > ROTATE_SETTLE_SECONDS)
                lines, consumed, more = self._read(old, cp.offset, max_lines, take_partial=settled)
                ref = datetime.fromtimestamp(old.stat().st_mtime, timezone.utc)
                if lines:
                    return Batch([(ln, ref) for ln in lines], [], replace(cp, offset=cp.offset + consumed), notes, True)
                if not settled:
                    return Batch([], [], cp, notes, False)
                newer = self._next_newer(old)
                if newer is not None:
                    # Several rotations happened since the checkpoint (e.g. the
                    # collector was stopped): read every generation in order.
                    notes.append(f"finished rotated file {old.name}; continuing with {newer.name}")
                    return Batch([], [], self._identity_of(newer), notes, True)
                notes.append(f"finished rotated file {old.name}; following new {self.path.name}")
            elif cp.offset > 0 and st is not None and (st.st_dev, st.st_ino) == (cp.dev, cp.inode):
                notes.append(f"log {self.path} was truncated or rewritten in place and no copy was found; "
                             "lines written after the last checkpoint may be missing")
            elif cp.offset > 0:
                notes.append(f"log {self.path} was replaced and the previous file was not found; "
                             "lines written to it after the last checkpoint may be missing")
            if st is None:
                return Batch([], [], cp, notes, False)
            cp = self._identity(st)

        if st.st_size < cp.offset:
            notes.append(f"log {self.path} shrank (truncated); reading again from the start")
            cp = self._identity(st)

        lines, consumed, more = self._read(self.path, cp.offset, max_lines, take_partial=False)
        new_cp = replace(cp, offset=cp.offset + consumed)
        if new_cp.fingerprint_len < FP_LEN and st.st_size > new_cp.fingerprint_len:
            fp = _head(self.path, FP_LEN)
            new_cp = replace(new_cp, fingerprint=fp, fingerprint_len=len(fp))
        ref = datetime.fromtimestamp(st.st_mtime, timezone.utc)
        return Batch([(ln, ref) for ln in lines], [], new_cp, notes, more)


def iter_file_lines(path: Path, max_line_bytes: int = 16384, chunk: int = 2000) -> Iterator[tuple[list[str], datetime]]:
    """Stream a whole (possibly gzip-compressed) file in bounded chunks."""
    ref = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    with _open(path) as fh:
        while True:
            lines, _, more = read_lines(fh, chunk, max_line_bytes, take_partial=True)
            if lines:
                yield lines, ref
            if not more:
                return


class JournaldSource:
    """Read Postfix-related journal entries after a stored cursor."""

    def __init__(self, journalctl: str, units: list[str], *, timeout: float = 30.0):
        self.journalctl = journalctl
        self.units = units
        self.timeout = timeout
        self.name = "journald"

    def command(self, cursor: str | None) -> list[str]:
        cmd = [self.journalctl, "--output=json", "--no-pager", "--quiet", "--all"]
        if cursor:
            cmd.append(f"--after-cursor={cursor}")
        for unit in self.units:
            cmd.extend(["--unit", unit])
        return cmd

    @staticmethod
    def entry_to_record(entry: dict) -> LogRecord | None:
        message = entry.get("MESSAGE")
        if isinstance(message, list):  # binary payloads are byte arrays
            message = bytes(message).decode("utf-8", errors="replace")
        if not isinstance(message, str):
            return None
        program = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM")
        try:
            ts = int(entry["__REALTIME_TIMESTAMP"])
        except (KeyError, ValueError):
            return None
        if not program:
            return None
        pid = entry.get("SYSLOG_PID") or entry.get("_PID")
        host = entry.get("_HOSTNAME", "")
        pid_text = f"[{pid}]" if pid else ""
        iso = datetime.fromtimestamp(ts / 1_000_000, timezone.utc).isoformat()
        return LogRecord(ts=ts, host=host, program=program, pid=int(pid) if pid and str(pid).isdigit() else None,
                         message=message, raw=f"{iso} {host} {program}{pid_text}: {message}")

    def poll(self, cp: Checkpoint | None, max_lines: int) -> Batch:
        cursor = cp.cursor if cp else None
        records: list[LogRecord] = []
        last_cursor = cursor
        more = False
        try:
            proc = subprocess.Popen(self.command(cursor), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    stdin=subprocess.DEVNULL)
        except OSError as exc:
            return Batch([], [], cp, [f"journalctl unavailable: {exc}"], False)
        deadline = time.monotonic() + self.timeout
        try:
            assert proc.stdout is not None
            for raw in proc.stdout:
                try:
                    entry = json.loads(raw)
                except ValueError:
                    continue
                last_cursor = entry.get("__CURSOR", last_cursor)
                record = self.entry_to_record(entry)
                if record is not None:
                    records.append(record)
                if len(records) >= max_lines or time.monotonic() > deadline:
                    more = True
                    break
        finally:
            proc.kill()
            proc.wait()
        new_cp = Checkpoint(path="journald", dev=0, inode=0, offset=0, fingerprint=b"", fingerprint_len=0,
                            cursor=last_cursor)
        return Batch([], records, new_cp, [], more)
