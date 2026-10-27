# BeastPing Mail Console

A lightweight, self-hosted dashboard for following each email through an
existing Postfix server. It reads Postfix log lines, correlates them into
messages and recipients, and shows activity, delivery outcomes, SMTP responses
and server health in a web interface inspired by Resend's dashboard.

It **does not send, relay or modify mail**. It never changes Postfix, Dovecot,
OpenDKIM, Mailguard, DNS or firewall settings, and it never restarts mail
services. It reads logs and runs two read-only status commands.

Phase 1 scope and its limits are listed under [Limitations](#limitations).

## What it shows

| Page | Contents |
|---|---|
| **Overview** | Accepted deliveries, deferrals, bounced/expired/rejected, error rate, current queue size, SMTP activity over time, destination domains, queue-size trend, recent problems. Ranges: 1h, 24h, 7d, 30d, 90d or custom. |
| **Emails** | One row per recipient: recipient (with sender), status, subject (only when Postfix logs it), relative "sent" time with the exact time on hover, and an actions menu (open, copy Queue ID, copy Message-ID). Toolbar: search, time range (24h/7d/15d/30d/90d/custom), status, sender (picked from senders actually seen) and CSV export. Filters combine with AND, live in the URL (bookmarkable) and survive paging and sorting. Sort by sent time, recipient or status; server-side pagination; whole rows are clickable. |
| **Email details** | Metadata (sender, recipients, subject, Message-ID, Queue ID, status, first/last/final timestamps, attempts, deferred attempts, relay, DSN), Delivery events (per-recipient table and a timeline of every log line, raw line included, redacted), related messages, and a Message content section that reads "Content not retained" unless an approved capture mechanism stored content. Missing evidence is stated explicitly. |
| **Monitoring** | Postfix, Mailguard, OpenDKIM and Dovecot unit state; queue size by queue, oldest message, queued entries with deferral reasons; collector health and checkpoint; recent operational warnings/errors from the logs. Read-only. |
| **Settings** | Administrator account, password change, active sessions, data retention, time zone, page size, theme (system/dark/light). |

### Status meanings

The console reports only what the logs prove.

| Status | Evidence |
|---|---|
| **Accepted by destination** | Postfix logged `status=sent`: the next-hop server answered SMTP 2xx. This is **not** proof of inbox placement, opening or reading. There is no open or click tracking, and a later asynchronous bounce from the destination is not correlated yet. |
| **Deferred** | Latest attempt was a temporary failure (`status=deferred`, 4xx or connection problem). Postfix will retry. |
| **Bounced** | Permanent failure (`status=bounced`, 5xx). |
| **Expired** | The queue manager logged `status=expired, returned to sender` after deferrals. |
| **Rejected** | Refused before delivery: `NOQUEUE: reject`, a milter reject (e.g. Mailguard) or a header/body check. |
| **Partially failed** | Some recipients accepted, others failed. |
| **Queued / Processing** | Received / scheduled, no final outcome logged yet. |
| **Removed** | Left the queue without a logged outcome (e.g. `postsuper -d`). |
| **Unknown** | The available evidence does not determine an outcome. |

Fields that never appeared in the logs are shown as *unknown*, not guessed.
Postfix logs subjects only if `header_checks` has an `INFO` rule for `Subject:`;
this console does not configure that.

## Architecture

```
/var/log/syslog ──read-only──▶ mail-console-collector ──▶ SQLite (WAL) ◀── mail-console-web ──▶ 127.0.0.1:8710
  (or journald)                 │  parse → correlate        /var/lib/mail-console          (FastAPI, server-rendered,
                                │  checkpoints, retention                                    no JavaScript)
systemctl show / postqueue -j ◀─┘  every 30 s (read-only)
```

* **Python 3.12**, FastAPI + Jinja2 templates, SVG charts rendered on the server,
  no JavaScript, no CDN, strict Content-Security-Policy.
* **SQLite** in WAL mode with explicit transactions and versioned migrations
  (`mailconsole/migrations`). No Redis, PostgreSQL, broker or Docker.
* Two **systemd services** under the unprivileged `mailconsole` user, heavily
  sandboxed, at low CPU/IO priority with memory caps.
* All runtime dependencies are pinned with hashes (`requirements.lock`) and are
  available as Linux ARM64 wheels (`scripts/check-arm64-wheels.sh`).

### How events become messages

1. **Read** – `FileSource` tails the log from a durable checkpoint (device, inode,
   byte offset and a fingerprint of the file head), committed in the same
   transaction as the events. It follows logrotate (rename, `delaycompress`,
   immediate `.gz` compression, `copytruncate`), finishes the rotated file before
   switching, never consumes a half-written line and reports gaps it cannot
   recover. Work is bounded: at most `MC_BATCH_LINES` lines per transaction and
   `MC_MAX_LINE_BYTES` per line. Web requests never read log files.
2. **Parse** – ISO 8601 (Ubuntu 24.04 default, any offset) and traditional
   syslog timestamps (zone `MC_LOG_TIMEZONE`, year inferred) are converted to UTC.
   Program names such as `postfix/submission/smtpd` are understood. Credential-like
   strings are redacted before storage.
3. **Store** – every event keeps a hash of its log line, so re-reading the same
   line (restart, overlap between import and live tailing) is a no-op.
4. **Correlate** – a *message* is one lifetime of a Postfix queue file. Because
   short Queue IDs are reused, all stored events of each touched Queue ID are
   re-split into lifetimes after every batch, in time order: a new lifetime
   starts after a `removed`/`requeued` record, at a second start record
   (`client=`/`pickup`), or after silence longer than `MC_QUEUE_REUSE_GAP_HOURS`.
   Message ids stay stable as evidence is added. Postfix-generated bounce
   notices, `postsuper -r` requeues and hand-offs to a local relay
   (`queued as …`) are linked to their original message. A reject at RCPT
   stage affects only that recipient.
5. **Derive** – message and per-recipient state is recomputed from the stored
   events after each batch, so the result does not depend on ingestion order
   (tested by ingesting the fixture forward, reversed and shuffled).

### Search

Search is case-insensitive and matches inside recipient and sender addresses,
Queue IDs, Message-IDs, subjects (when logged), destination domains and the
SMTP responses of failed recipients.

* Terms of **3 or more characters** use an SQLite **FTS5 trigram index**
  (`message_search`, one document per message, kept in step by the collector).
  The index selects candidate messages; a row-level check then keeps only
  recipient rows that actually contain the term, so searching one recipient of
  a multi-recipient message does not list the others.
* **Shorter terms** match only an exact Queue ID, recipient address or domain
  (indexed equality); the page says so.
* User input is never interpreted as FTS or SQL syntax: it is bound as a
  quoted FTS phrase and as `instr()` arguments, so `%`, `_`, quotes and FTS
  operators match literally.
* Result counts stop at 10,000 ("10,000+") so a broad search costs a bounded
  amount of work; narrow the search or range to page further.
* Filtering by status, sender or time uses indexes on `messages`; the
  combination of a broad time range with a rare status still walks that time
  range. `scripts/bench_search.py` measures all of this on synthetic data;
  with 100,000 messages over 90 days, page loads take 0.2–65 ms, a search for a
  very common term ("example.org", 10,000+ matches) about 210 ms, and a 50,000-row
  CSV export about 175 ms (x86-64 development machine).

### Growth controls

* Retention (default 90 days, Settings) deletes messages by last activity, hourly.
* `MC_MAX_DB_MB` (default 2048) caps live database size; oldest history goes first.
* `MC_MAX_EVENTS_PER_MESSAGE` caps stored retry events per message; final outcomes
  are always kept and the detail page says when counts are lower bounds.
* Queue snapshots keep counts for 14 days and the entry list only for the latest.

## Installation

Short version (full procedure, configuration review, reverse proxy, update,
rollback and uninstall: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)):

```bash
sudo apt-get install -y python3.12-venv git
sudo git clone https://github.com/enazari7/mail-console.git /usr/local/src/mail-console
cd /usr/local/src/mail-console
sudo ./deploy/install.sh --no-start
sudoedit /etc/mail-console/mail-console.env
sudo mail-console check
sudo mail-console admin create --username admin
sudo systemctl start mail-console-collector mail-console-web
```

Then open it through an SSH tunnel: `ssh -N -L 8710:127.0.0.1:8710 <admin>@<mail-server>`
and browse to <http://localhost:8710>.

## Command line

All commands run as the service user through the `/usr/local/sbin/mail-console` wrapper:

| Command | Purpose |
|---|---|
| `mail-console check` | Configuration, permissions, log readability, unit and queue status (changes nothing) |
| `mail-console parse-check FILE` | Dry run: what the parser recognises in a log file (writes nothing) |
| `mail-console import --rotated [--include-current] [FILE...]` | Historical import, oldest first, idempotent; refuses while the collector runs |
| `mail-console admin create\|reset-password\|list\|delete` | Administrator accounts (`--password-stdin` for automation) |
| `mail-console admin unlock` | Clear login throttling after repeated failed attempts |
| `mail-console migrate` | Apply database migrations |
| `mail-console purge` | Apply retention now |
| `mail-console reindex` | Rebuild the full-text search index (normally maintained automatically) |
| `mail-console serve` / `collect` | What the systemd units run |

## Development

```bash
python3.12 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
.venv/bin/ruff check mailconsole tests
```

Run locally against the sanitized fixture (no root, no real logs):

```bash
cat > /tmp/mc.env <<EOF
MC_DATA_DIR=/tmp/mc-data
MC_LOG_PATH=$PWD/tests/fixtures/syslog-iso.log
MC_COOKIE_SECURE=false
EOF
.venv/bin/python -m mailconsole --env-file /tmp/mc.env migrate
.venv/bin/python -m mailconsole --env-file /tmp/mc.env admin create --username admin
.venv/bin/python -m mailconsole --env-file /tmp/mc.env collect &
.venv/bin/python -m mailconsole --env-file /tmp/mc.env serve
```

Synthetic data for demos and benchmarks (reserved example domains only):

```bash
.venv/bin/python scripts/demo_data.py --messages 2000 --days 15 > /tmp/demo-syslog
.venv/bin/python scripts/bench_search.py --messages 100000 --days 90
```

Tests cover parsing, Queue ID correlation and reuse, multiple recipients,
retries and final outcomes, duplicates, rotation and restart, time zones,
authentication and sessions, search/filter/pagination, storage and migrations,
monitoring commands and the deployment artefacts. CI runs them on x86-64 and
ARM64 and performs a full `install.sh` → acceptance → update → rollback →
uninstall cycle on an Ubuntu 24.04 ARM64 runner without Docker.

## Limitations

* **No inbox, open or click data.** SMTP acceptance is the furthest point the
  logs can prove. Nothing is fabricated.
* **Asynchronous bounces** (a remote server accepts, then later mails a DSN) are
  handled by the existing BeastPing bounce processor; this console does not read
  its ledger yet, so such messages remain *Accepted* here. A read-only
  integration needs a separate review.
* A hand-off to a local after-queue content filter is shown as accepted for the
  first queue file and linked to the queue file it continues as; both count in
  the overview totals. (Mailguard is a milter, so the current setup has no such
  hand-off.)
* **Subjects** appear only if Postfix logs them (requires a `header_checks`
  change that is out of scope).
* **Single role.** Every account is a full administrator; there is no 2FA.
  Use an SSH tunnel or a reverse proxy with network restrictions.
* **Search** substring matching needs 3+ characters; status-only filters over
  long ranges walk that range (see [Search](#search)). Counts are capped at 10,000.
* **Receiving** (inbound mail) is not tracked; the tab is shown as unavailable.
* **Message content** is not captured. The UI and a `message_content` table are
  ready for a future, separately approved capture service; HTML would render only
  in a sandboxed, script-free frame with remote resources blocked.
* **Charts** bucket by the display zone's UTC offset at the end of the range;
  across a DST change, day buckets shift by an hour.
* **journald source** is implemented and tested with a simulated `journalctl`;
  the file source is the primary, end-to-end-tested path.
* Parsing is tested against sanitized fixtures modelled on Ubuntu 24.04 Postfix
  logs, not against the production logs themselves; run `mail-console parse-check`
  on the server as part of acceptance.
* Not feature-equivalent to Resend: no sending API, webhooks, audiences,
  templates or engagement tracking.

## Security

See [SECURITY.md](SECURITY.md).
