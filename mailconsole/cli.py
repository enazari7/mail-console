"""Command-line entry point: ``mail-console <command>``."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys
from collections import Counter
from pathlib import Path

from . import __version__

DEFAULT_ENV_FILE = "/etc/mail-console/mail-console.env"


def load_env_file(path: str | None = None) -> str | None:
    """Load KEY=VALUE lines into os.environ without overriding existing values."""
    path = path or os.environ.get("MC_ENV_FILE") or DEFAULT_ENV_FILE
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError):
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key.startswith("MC_"):
            os.environ.setdefault(key, value)
    return path


def _read_new_password(args) -> str:
    if args.password_stdin:
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass("New password (12+ characters): ")
    second = getpass.getpass("Repeat password: ")
    if first != second:
        raise SystemExit("passwords do not match")
    return first


def cmd_migrate(cfg, args) -> int:
    from .db import connect, migrate
    conn = connect(cfg.db_path)
    applied = migrate(conn)
    conn.close()
    print(f"applied: {', '.join(applied)}" if applied else "schema is up to date")
    return 0


def cmd_serve(cfg, args) -> int:
    from .web import run_server
    run_server(cfg)
    return 0


def cmd_collect(cfg, args) -> int:
    from .collector import main as collector_main
    collector_main(cfg)
    return 0


def cmd_import(cfg, args) -> int:
    from .collector import LockBusy, import_files
    from .sources import rotated_siblings
    paths = [Path(p) for p in args.files]
    if args.rotated:
        paths = rotated_siblings(cfg.log_path) + paths
    if args.include_current:
        paths.append(cfg.log_path)
    if not paths:
        print("nothing to import: pass files, --rotated and/or --include-current", file=sys.stderr)
        return 2
    try:
        stats = import_files(cfg, paths)
    except LockBusy as exc:
        print(f"error: {exc}. Stop mail-console-collector first: systemctl stop mail-console-collector",
              file=sys.stderr)
        return 1
    print(f"total: {stats.events} new events, {stats.duplicates} duplicates skipped, "
          f"{len(stats.messages_touched)} messages updated")
    return 0


def cmd_admin(cfg, args) -> int:
    from . import auth
    from .db import connect, pending_migrations
    conn = connect(cfg.db_path)
    if pending_migrations(conn):
        print("run 'mail-console migrate' first", file=sys.stderr)
        return 1
    try:
        if args.admin_cmd == "create":
            admin_id = auth.create_admin(conn, args.username, _read_new_password(args))
            print(f"created administrator {args.username!r} (id {admin_id})")
        elif args.admin_cmd == "reset-password":
            row = conn.execute("SELECT id FROM admins WHERE username = ?", (args.username,)).fetchone()
            if row is None:
                print(f"no administrator named {args.username!r}", file=sys.stderr)
                return 1
            auth.set_password(conn, row[0], _read_new_password(args))
            print(f"password changed for {args.username!r}; all of its sessions were signed out")
        elif args.admin_cmd == "list":
            for row in conn.execute("SELECT username, created_ts, last_login_ts FROM admins ORDER BY id"):
                print(row[0])
        elif args.admin_cmd == "totp-disable":
            row = conn.execute("SELECT id FROM admins WHERE username = ?", (args.username,)).fetchone()
            if row is None:
                print(f"no administrator named {args.username!r}", file=sys.stderr)
                return 1
            auth.totp_disable(conn, row[0])
            print(f"two-factor authentication disabled for {args.username!r}")
        elif args.admin_cmd == "unlock":
            print(f"cleared {auth.clear_failures(conn)} failed login attempt(s)")
        elif args.admin_cmd == "delete":
            from .db import tx
            with tx(conn):
                n = conn.execute("DELETE FROM admins WHERE username = ?", (args.username,)).rowcount
            print("deleted" if n else "not found")
    except auth.AuthError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 0


def cmd_purge(cfg, args) -> int:
    from .collector import apply_retention, require_schema
    from .db import connect
    conn = connect(cfg.db_path)
    require_schema(conn)
    print(apply_retention(conn, cfg))
    conn.close()
    return 0


def cmd_reindex(cfg, args) -> int:
    from . import search
    from .collector import require_schema
    from .db import connect
    conn = connect(cfg.db_path)
    require_schema(conn)
    print(f"rebuilt {search.rebuild(conn):,} search documents")
    conn.close()
    return 0


def cmd_archive(cfg, args) -> int:
    from . import archive
    from .collector import require_schema
    from .db import connect
    conn = connect(cfg.db_path)
    require_schema(conn)
    if args.archive_cmd == "status":
        for key, value in archive.status(conn, cfg).items():
            print(f"{key:<20} {value}")
        return 0
    store = archive.open_store(cfg)
    bad = 0
    rows = conn.execute("SELECT sha256, path FROM archive_blobs ORDER BY sha256").fetchall()
    for sha, rel in rows:
        if not store.verify(rel, sha):
            bad += 1
            print(f"FAIL  {rel}: missing, unreadable, tampered or wrong key")
    print(f"verified {len(rows) - bad} of {len(rows)} stored messages")
    return 1 if bad else 0


def cmd_parse_check(cfg, args) -> int:
    """Dry run: parse a log file and summarise what would be ingested. Writes nothing."""
    from .parser import classify, parse_syslog_line
    from .sources import iter_file_lines
    kinds: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    unparsed = other_qid = total = 0
    for lines, ref in iter_file_lines(Path(args.file), cfg.max_line_bytes):
        for line in lines:
            total += 1
            rec = parse_syslog_line(line, bsd_tz=cfg.log_timezone, reference=ref)
            if rec is None:
                unparsed += 1
                continue
            item = classify(rec, cfg.postfix_prefixes, cfg.ops_programs, cfg.archive_recipient)
            if item is None:
                continue
            if item.ops:
                kinds[f"ops:{item.ops.level}"] += 1
            else:
                kinds[item.event.kind] += 1
                if item.event.kind == "delivery":
                    statuses[item.event.status] += 1
                if item.event.kind == "other":
                    other_qid += 1
    print(f"lines: {total}  unrecognised syslog format: {unparsed}")
    for kind, n in sorted(kinds.items()):
        print(f"  {kind:<20} {n}")
    for status, n in sorted(statuses.items()):
        print(f"  delivery status={status:<12} {n}")
    if other_qid:
        print(f"note: {other_qid} queue-ID lines did not match a known pattern; they are kept as 'other' events")
    return 0


def cmd_check(cfg, args) -> int:
    """Check configuration, permissions and read access. Changes nothing."""
    from . import monitor
    from .db import connect, pending_migrations
    ok = True
    def report(good: bool, text: str) -> None:
        nonlocal ok
        ok &= good
        print(("ok    " if good else "FAIL  ") + text)
    report(cfg.bind_host in ("127.0.0.1", "::1", "localhost"),
           f"web binds to {cfg.bind_host}:{cfg.port} (loopback expected)")
    if cfg.log_source == "file":
        try:
            with open(cfg.log_path, "rb") as fh:
                fh.read(1)
            report(True, f"log file {cfg.log_path} is readable")
        except OSError as exc:
            report(False, f"log file {cfg.log_path}: {exc.strerror}")
    try:
        conn = connect(cfg.db_path)
        pending = pending_migrations(conn)
        report(not pending, "database schema up to date" if not pending else f"pending migrations: {pending}")
        if not pending:
            from . import search
            missing = search.missing_documents(conn)
            report(missing == 0, "search index complete" if not missing
                   else f"search index missing {missing} message(s); run 'mail-console reindex'")
        conn.close()
        mode = os.stat(cfg.db_path).st_mode & 0o777
        report(mode & 0o077 == 0, f"database file mode {mode:o}")
        dmode = os.stat(cfg.data_dir).st_mode & 0o777
        report(dmode & 0o007 == 0, f"data directory mode {dmode:o}")
    except Exception as exc:  # noqa: BLE001 - diagnostic command
        report(False, f"database: {exc}")
    for label, unit in cfg.monitor_units:
        s = monitor.check_unit(cfg.systemctl_cmd, label, unit)
        print(("ok    " if s.ok else "warn  ") + f"{label} ({unit}): {s.active_state or s.error}")
    if cfg.archive_enabled:
        from .blobstore import load_key
        spool = cfg.archive_spool
        print(("ok    " if spool.is_dir() else "warn  ") + f"archive spool {spool}"
              + ("" if spool.is_dir() else " missing (message capture not set up)"))
        try:
            key = load_key(cfg.archive_key_file)
            print(("ok    " if key else "warn  ") + "archive encryption key "
                  + ("loaded" if key else f"not found at {cfg.archive_key_file} (stored content is not encrypted)"))
        except (OSError, ValueError) as exc:
            report(False, f"archive encryption key: {exc}")
    q = monitor.check_queue(cfg.postqueue_cmd)
    print(("ok    " if q.ok else "warn  ") + (f"postqueue: {q.total} queued" if q.ok else f"postqueue: {q.error}"))
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mail-console", description="BeastPing Mail Console")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--env-file", help=f"environment file (default {DEFAULT_ENV_FILE} if readable)")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="run the web interface")
    sub.add_parser("collect", help="run the log collector daemon")
    sub.add_parser("migrate", help="apply database migrations")
    imp = sub.add_parser("import", help="import existing log files (idempotent)")
    imp.add_argument("files", nargs="*", help="log files (.gz allowed), oldest first")
    imp.add_argument("--rotated", action="store_true", help="import rotated copies of MC_LOG_PATH, oldest first")
    imp.add_argument("--include-current", action="store_true", help="also import MC_LOG_PATH itself")
    admin = sub.add_parser("admin", help="manage administrator accounts")
    admin_sub = admin.add_subparsers(dest="admin_cmd", required=True)
    for name in ("create", "reset-password"):
        a = admin_sub.add_parser(name)
        a.add_argument("--username", required=True)
        a.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    admin_sub.add_parser("list")
    admin_sub.add_parser("unlock", help="clear login throttling (failed attempts)")
    td = admin_sub.add_parser("totp-disable", help="remove two-factor authentication (recovery)")
    td.add_argument("--username", required=True)
    arc = sub.add_parser("archive", help="message archive maintenance")
    arc_sub = arc.add_subparsers(dest="archive_cmd", required=True)
    arc_sub.add_parser("status", help="show archive health")
    arc_sub.add_parser("verify", help="re-hash every stored message and check rows against files")
    d = admin_sub.add_parser("delete")
    d.add_argument("--username", required=True)
    sub.add_parser("purge", help="apply retention now")
    sub.add_parser("reindex", help="rebuild the full-text search index")
    pc = sub.add_parser("parse-check", help="dry-run parse of a log file (writes nothing)")
    pc.add_argument("file")
    sub.add_parser("check", help="check configuration and access (changes nothing)")
    return p


COMMANDS = {
    "serve": cmd_serve, "collect": cmd_collect, "migrate": cmd_migrate, "import": cmd_import,
    "admin": cmd_admin, "purge": cmd_purge, "reindex": cmd_reindex, "parse-check": cmd_parse_check,
    "check": cmd_check, "archive": cmd_archive,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    load_env_file(args.env_file)
    logging.basicConfig(level=os.environ.get("MC_LOG_LEVEL", "INFO").upper(),
                        format="%(levelname)s %(name)s: %(message)s")
    from .config import ConfigError, load_config
    try:
        cfg = load_config()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    os.umask(0o077)
    return COMMANDS[args.command](cfg, args)
