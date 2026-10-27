#!/usr/bin/env python3
"""Benchmark Emails-page queries on a synthetic database (no real data).

    python3 scripts/bench_search.py --messages 100000 --days 90

Builds a temporary database from scripts/demo_data.py output through the real
parser/correlator, then times the queries the Emails page and CSV export run.
"""

from __future__ import annotations

import argparse
import os
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mailconsole import queries  # noqa: E402
from mailconsole.collector import import_files  # noqa: E402
from mailconsole.config import load_config  # noqa: E402
from mailconsole.db import connect, migrate  # noqa: E402

DAY = 86400 * 1_000_000


def timed(fn, repeat=5):
    samples = []
    for _ in range(repeat):
        t = time.perf_counter()
        result = fn()
        samples.append((time.perf_counter() - t) * 1000)
    return statistics.median(samples), result


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--messages", type=int, default=100_000)
    p.add_argument("--days", type=float, default=90)
    p.add_argument("--keep", help="directory to keep the generated database in")
    args = p.parse_args()
    work = Path(args.keep or tempfile.mkdtemp(prefix="mc-bench-"))
    work.mkdir(parents=True, exist_ok=True)
    log = work / "syslog"
    end = "2026-10-27T12:00:00+00:00"
    with open(log, "w") as fh:
        subprocess.run([sys.executable, str(ROOT / "scripts" / "demo_data.py"), "--messages", str(args.messages),
                        "--days", str(args.days), "--end", end], stdout=fh, check=True)
    os.environ.update({"MC_DATA_DIR": str(work / "data"), "MC_LOG_PATH": str(log), "MC_BATCH_LINES": "5000"})
    cfg = load_config()
    conn = connect(cfg.db_path)
    migrate(conn)
    lines = sum(1 for _ in open(log))
    t = time.perf_counter()
    import_files(cfg, [log], echo=lambda _: None)
    ingest_s = time.perf_counter() - t
    conn.execute("ANALYZE")
    now = int(datetime.fromisoformat(end).timestamp()) * 1_000_000
    rows = conn.execute("SELECT count(*) FROM recipients").fetchone()[0]
    size = sum(os.path.getsize(str(cfg.db_path) + s) for s in ("", "-wal") if os.path.exists(str(cfg.db_path) + s))
    fts = conn.execute("SELECT sum(pgsize) FROM dbstat WHERE name LIKE 'message_search%'").fetchone()[0] \
        if conn.execute("SELECT 1 FROM pragma_compile_options WHERE compile_options = 'ENABLE_DBSTAT_VTAB'").fetchone() else None
    print(f"messages={args.messages:,} recipients={rows:,} log_lines={lines:,} days={args.days:g}")
    print(f"ingest: {ingest_s:.1f} s ({lines / ingest_s:,.0f} lines/s); database {size / 2**20:.1f} MiB"
          + (f", search index {fts / 2**20:.1f} MiB" if fts else ""))
    F = queries.ActivityFilter
    cases = [
        ("list, last 15 days, page 1", F(start=now - 15 * DAY, end=now), 1),
        ("list, last 90 days, page 1", F(start=now - 90 * DAY, end=now), 1),
        ("list, last 90 days, page 100", F(start=now - 90 * DAY, end=now), 100),
        ("search common term 'example.org', 90 d", F(q="example.org", start=now - 90 * DAY, end=now), 1),
        ("search recipient fragment 'omid12', 90 d", F(q="omid12", start=now - 90 * DAY, end=now), 1),
        ("search Queue ID prefix, 90 d", None, 1),
        ("search error text 'user unknown', 90 d", F(q="user unknown", start=now - 90 * DAY, end=now), 1),
        ("status=bounced, 90 d", F(status="bounced", start=now - 90 * DAY, end=now), 1),
        ("sender=billing@, 90 d", F(sender="billing@example.com", start=now - 90 * DAY, end=now), 1),
        ("status+sender+search, 90 d", F(q="example.net", status="accepted", sender="notify@example.com",
                                         start=now - 90 * DAY, end=now), 1),
        ("sort by recipient, 90 d", F(sort="recipient", direction="asc", start=now - 90 * DAY, end=now), 1),
        ("sort by status, 15 d", F(sort="status", start=now - 15 * DAY, end=now), 1),
    ]
    qid = conn.execute("SELECT queue_id FROM messages WHERE queue_id IS NOT NULL LIMIT 1 OFFSET 777").fetchone()[0]
    print(f"\n{'query':<46}{'median ms':>10}{'rows':>8}{'total':>9}")
    for name, f, page in cases:
        if f is None:
            f = F(q=qid[:6], start=now - 90 * DAY, end=now)
        ms, res = timed(lambda f=f, page=page: queries.activity(conn, f, page, 50))
        total = f"{res['total']:,}{'+' if res['capped'] else ''}"
        print(f"{name:<46}{ms:>10.1f}{len(res['rows']):>8}{total:>9}")
    ms, senders = timed(lambda: queries.senders(conn, now - 90 * DAY, now))
    print(f"{'sender picker, 90 d':<46}{ms:>10.1f}{len(senders):>8}")
    t = time.perf_counter()
    n = sum(1 for _ in queries.export_rows(conn, F(start=now - 90 * DAY, end=now), 50_000))
    print(f"{'CSV export rows (50,000 cap), 90 d':<46}{(time.perf_counter() - t) * 1000:>10.1f}{n:>8}")
    print(f"\nwork dir: {work}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
