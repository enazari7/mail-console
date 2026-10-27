#!/usr/bin/env python3
"""Postfix pipe(8) delivery agent that spools a copy of a message for the archive.

Runs for the archive recipient added by ``always_bcc`` (see docs/MAIL-CAPTURE.md):

    argv=/usr/local/libexec/mail-console/mc-capture --queue-id=${queue_id} --sender=${sender}
         --sasl-user=${sasl_username}

Design constraints (the mail path must never depend on the console):

* Standard library only; started as ``python3 -I`` so the console's
  virtualenv, database and services are not involved.
* Streams stdin to a temporary file (no full message in memory), fsyncs it,
  then publishes ``<name>.eml`` and finally ``<name>.json`` with atomic
  renames. A message counts as captured only when its ``.json`` exists.
* Exit 0 after both files are durable.
* Storage pressure never holds mail in the Postfix queue: when the spool
  exceeds ``--max-spool-mb``, the disk has less than ``--min-free-mb`` free,
  or a write fails with ENOSPC/EDQUOT, the message is read and discarded and
  a small ``<name>.skipped.json`` marker records the skip (exit 0). The
  console shows the skip on the message and raises an alert. (Holding the
  copy would keep the whole queue file on a disk that is already full.)
* Any other problem (bad arguments, missing spool, unexpected error) exits 75
  (EX_TEMPFAIL): Postfix retries only the archive copy; real recipients are
  unaffected and always_bcc uses NOTIFY=NONE, so the sender is never notified.
* Never modifies the message bytes.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import secrets
import socket
import sys
import time

EX_OK = 0
EX_TEMPFAIL = 75
CHUNK = 1 << 16
QUEUE_ID_RE = re.compile(r"^[0-9A-Za-z]{6,20}$")
DEFAULT_SPOOL = "/var/spool/mail-console/incoming"
DEFAULT_MIN_FREE_MB = 1024
DEFAULT_MAX_SPOOL_MB = 2048
FREE_CHECK_EVERY = 4 << 20  # re-check free space every 4 MiB written


class TempFail(Exception):
    pass


class Skip(Exception):
    """Storage pressure: record a skip instead of holding mail in the queue."""

    def __init__(self, reason: str, digest=None, size: int = 0):
        super().__init__(reason)
        self.digest = digest
        self.size = size


def free_bytes(path: str) -> int:
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def spool_bytes(spool: str) -> int:
    total = 0
    with os.scandir(spool) as entries:
        for entry in entries:
            if entry.name.endswith(".eml") or entry.name.startswith(".tmp-"):
                try:
                    total += entry.stat(follow_symlinks=False).st_size
                except FileNotFoundError:
                    continue
    return total


def write_skip(stream, spool: str, queue_id: str, sender: str, sasl_user: str, reason: str, now_us: int,
               digest=None, size: int = 0) -> str:
    """Consume the rest of the message and leave a durable marker that it was not archived."""
    digest = digest or hashlib.sha256()
    for chunk in iter(lambda: stream.read(CHUNK), b""):
        digest.update(chunk)
        size += len(chunk)
    base = f"{now_us}-{queue_id}-{secrets.token_hex(4)}"
    meta = {"version": 1, "skipped": reason, "queue_id": queue_id, "sender": sender, "sasl_username": sasl_user,
            "captured_us": now_us, "size": size, "sha256": digest.hexdigest(), "host": socket.gethostname()}
    tmp = os.path.join(spool, f".tmp-{base}.skipped.json")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        try:
            os.write(fd, json.dumps(meta, separators=(",", ":")).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp, os.path.join(spool, base + ".skipped.json"))
    except OSError:
        # Even the marker cannot be written (disk completely full). The console
        # still detects the gap: Postfix logged the copy as delivered, but no
        # archive or marker exists for it.
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return base


def capture(stream, spool: str, queue_id: str, sender: str, sasl_user: str, min_free: int,
            now_us: int | None = None, max_spool: int | None = None) -> str:
    """Write the message from ``stream`` into ``spool``; return the base name."""
    if not QUEUE_ID_RE.match(queue_id):
        raise TempFail(f"invalid queue id {queue_id!r}")
    if not os.path.isdir(spool):
        raise TempFail(f"spool directory {spool} does not exist")
    if free_bytes(spool) < min_free:
        raise Skip("less than the minimum free disk space on the archive spool")
    if max_spool is not None and spool_bytes(spool) >= max_spool:
        raise Skip("archive spool is full (the console is not ingesting)")
    now_us = now_us or time.time_ns() // 1000
    base = f"{now_us}-{queue_id}-{secrets.token_hex(4)}"
    tmp = os.path.join(spool, f".tmp-{base}")
    digest = hashlib.sha256()
    size = 0
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    try:
        since_check = 0
        while True:
            chunk = stream.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                try:
                    written = os.write(fd, view)
                except OSError as exc:
                    if exc.errno in (errno.ENOSPC, errno.EDQUOT):
                        raise Skip("disk full while writing the archive copy", digest, size + len(chunk)) from exc
                    raise
                view = view[written:]
            size += len(chunk)
            since_check += len(chunk)
            if since_check >= FREE_CHECK_EVERY:
                since_check = 0
                if free_bytes(spool) < min_free:
                    raise Skip("archive spool ran low on disk space while writing", digest, size)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.close(fd)

    meta = {
        "version": 1,
        "queue_id": queue_id,
        "sender": sender,
        "sasl_username": sasl_user,
        "captured_us": now_us,
        "size": size,
        "sha256": digest.hexdigest(),
        "host": socket.gethostname(),
    }
    eml = os.path.join(spool, base + ".eml")
    meta_tmp = os.path.join(spool, f".tmp-{base}.json")
    try:
        os.rename(tmp, eml)
        mfd = os.open(meta_tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        try:
            os.write(mfd, json.dumps(meta, separators=(",", ":")).encode())
            os.fsync(mfd)
        finally:
            os.close(mfd)
        os.rename(meta_tmp, os.path.join(spool, base + ".json"))
        fsync_dir(spool)
    except BaseException:
        for leftover in (tmp, eml, meta_tmp):
            try:
                os.unlink(leftover)
            except OSError:
                pass
        raise
    return base


def main(argv: list[str] | None = None, stdin=None) -> int:
    parser = argparse.ArgumentParser(prog="mc-capture", add_help=True)
    parser.add_argument("--queue-id", required=True)
    parser.add_argument("--sender", default="")
    parser.add_argument("--sasl-user", default="")
    parser.add_argument("--spool", default=os.environ.get("MC_CAPTURE_SPOOL", DEFAULT_SPOOL))
    parser.add_argument("--min-free-mb", type=int, default=DEFAULT_MIN_FREE_MB)
    parser.add_argument("--max-spool-mb", type=int, default=DEFAULT_MAX_SPOOL_MB)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return EX_TEMPFAIL
    os.umask(0o027)
    stream = stdin or sys.stdin.buffer
    try:
        capture(stream, args.spool, args.queue_id, args.sender, args.sasl_user, args.min_free_mb * 1024 * 1024,
                max_spool=args.max_spool_mb * 1024 * 1024)
    except Skip as exc:
        write_skip(stream, args.spool, args.queue_id, args.sender, args.sasl_user, str(exc), time.time_ns() // 1000,
                   exc.digest, exc.size)
        return EX_OK
    except TempFail as exc:
        print(f"mail-console capture deferred: {exc}", file=sys.stderr)
        return EX_TEMPFAIL
    except Exception as exc:  # noqa: BLE001 - any failure must be a temporary failure for Postfix
        print(f"mail-console capture deferred: {exc.__class__.__name__}: {exc}"[:300], file=sys.stderr)
        return EX_TEMPFAIL
    return EX_OK


if __name__ == "__main__":
    sys.exit(main())
