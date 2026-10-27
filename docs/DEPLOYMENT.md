# Deployment, update, rollback and uninstall

Target: Ubuntu 24.04 (ARM64 or x86-64), Python 3.12, systemd. No Docker.
Nothing here is run automatically; every step is executed by an administrator.

## What installation changes on the host

| Created / changed | Notes |
|---|---|
| System user and group `mailconsole` | `nologin`, home `/var/lib/mail-console` |
| `/opt/mail-console/releases/<release>/` and the `current` symlink | Code and its own virtualenv, root-owned |
| `/etc/mail-console/mail-console.env` | Created from `.env.example` only if missing; never overwritten |
| `/var/lib/mail-console/` | Database, backups, collector lock |
| `/etc/systemd/system/mail-console-web.service`, `mail-console-collector.service` (+ `.d/10-groups.conf`) | Only these two units are enabled/started |
| `/usr/local/sbin/mail-console` | CLI wrapper running as `mailconsole` |

Not touched: Postfix (configuration, listeners, queue), Dovecot, OpenDKIM, the
Mailguard milter, the existing bounce collector/worker and its SQLite ledger,
SMTP credentials, DKIM keys, DNS, firewall, rsyslog/logrotate, the Django
BeastPing application. No mail is sent.

Runtime footprint: the collector polls the log every 2 s and runs
`systemctl show` and `postqueue -j` every 30 s, at `Nice=10`, idle I/O class,
`MemoryMax=512M`; the web service is capped at 384 MB. Measured resident memory is
about 25 MB (collector) and 60 MB (web) in testing, plus 64 MiB transiently while a password is hashed at login.

## Install

Requires outbound HTTPS to PyPI for the hash-pinned wheels.

```bash
sudo apt-get install -y python3.12-venv git
sudo git clone https://github.com/enazari7/mail-console.git /usr/local/src/mail-console
cd /usr/local/src/mail-console
sudo git checkout <reviewed commit SHA>
sudo ./deploy/install.sh --no-start
```

Review the configuration:

```bash
sudoedit /etc/mail-console/mail-console.env
```

* `MC_LOG_PATH=/var/log/syslog` (or `/var/log/mail.log`, which contains only mail
  facility lines and is smaller; both work).
* `MC_MONITOR_UNITS`: confirm unit names, especially Mailguard's:
  `systemctl list-units --all --type=service | grep -Ei 'postfix|guard|dkim|dovecot|bounce'`.
  Additional units (e.g. the bounce collector/worker) can be appended as `Label=unit`.
* `MC_LOG_TIMEZONE`: only used for traditional-format lines without an offset.

Verify read access and parsing without writing anything:

```bash
sudo mail-console check
sudo mail-console parse-check /var/log/syslog
```

`parse-check` prints counts per event type and delivery status. Compare with
`grep -c 'status=sent' /var/log/syslog` etc. if in doubt.

Optional historical import of rotated logs (idempotent; run before the collector
starts, it refuses while the collector runs):

```bash
sudo mail-console import --rotated
```

The collector itself reads the current `/var/log/syslog` from the beginning on
its first start, then follows it.

Create the administrator (prompts for a password, 12+ characters):

```bash
sudo mail-console admin create --username admin
```

Start the console services:

```bash
sudo systemctl start mail-console-collector mail-console-web
systemctl status mail-console-collector mail-console-web
```

## Access

The web interface listens on `127.0.0.1:8710` only.

**SSH tunnel (recommended):**

```bash
ssh -N -L 8710:127.0.0.1:8710 <admin-user>@<mail-server>
```

Then open <http://localhost:8710>. Browsers treat `localhost` as a secure
context, so the `Secure` session cookie works over the tunnel.

**HTTPS reverse proxy (later, separately approved):** see
`deploy/nginx-example.conf`. Restrict by source network or VPN, keep TLS, and set
`MC_ALLOWED_HOSTS=<name>` and `MC_TRUST_PROXY=true`, then
`sudo systemctl restart mail-console-web`. Do not change `MC_BIND` to a public
address.

## Acceptance

Follow [ACCEPTANCE.md](ACCEPTANCE.md). The automated part:

```bash
printf '%s\n' '<admin password>' | python3 /opt/mail-console/current/deploy/smoke_test.py \
  --username admin --password-stdin --expect <a recent Queue ID> --expect <a recent recipient>
```

## Update

```bash
cd /usr/local/src/mail-console
sudo git fetch && sudo git checkout <reviewed commit SHA>
sudo ./deploy/update.sh
```

`update.sh` installs a new release next to the current one, stops the two
console services (never the mail services), backs up the database to
`/var/lib/mail-console/backups/pre-<release>.sqlite3` (last 5 kept), applies
migrations, switches the `current` symlink atomically, starts the console
services again and waits for `/healthz`. If anything fails before the switch,
the previous release is started again automatically. While the console is
stopped, Postfix keeps logging; the collector catches up from its checkpoint. The previous release directory is
kept for rollback.

### Upgrading to the EMAILS-UX-02 release

* Migration `0002_search_and_content` adds the `message_search` FTS5 table, an
  empty `message_content` table and two indexes (one of them, on
  `events(queue_id, host)`, fixes slow correlation on large histories), then
  builds the search index for existing messages in chunks of 2,000. It runs
  inside `update.sh` before the services restart. Measured on the synthetic
  benchmark (x86-64 development machine): 5.3 s per 100,000 messages for the
  search index; expect it to take a few times longer on the ARM64 server.
* Storage: the 100,000-message / 90-day benchmark database is about 500 MiB
  (≈5 KB per message including the redacted raw log line of every event and a
  70 MiB search index). `MC_STORE_RAW_LINES=false` drops the raw lines;
  `MC_MAX_DB_MB` and retention bound the total.
* Requires SQLite with FTS5 and the trigram tokenizer (SQLite ≥ 3.34, both
  present in Ubuntu 24.04's `libsqlite3-0` 3.45). `mail-console check` reports
  "search index complete".
* No configuration changes are required. No new services, ports or dependencies.
* Search-index safety: every `migrate` completes missing documents (so an
  interrupted rebuild is finished by simply re-running `update.sh`), and the new
  collector re-synchronises the index at startup whenever an older collector has
  run since its last start. `sudo mail-console reindex` remains available.
* New default `MC_MONITOR_UNITS` in `.env.example` (an existing
  `/etc/mail-console/mail-console.env` is never overwritten): consider adding
  `Postfix-master=postfix@-.service` to it, because `postfix.service` on Ubuntu
  is a one-shot wrapper that stays "active (exited)" even if the Postfix master
  process stops.

### Upgrading to the MAIL-CONTENT-01 release

* Migration `0003_mail_content` adds the archive tables, an archive search
  index, the audit log, TOTP columns and per-message archive-copy state, and
  drops the always-empty `message_content` placeholder.
* `install.sh`/`update.sh` additionally create the user `mcarchive`,
  `/var/spool/mail-console/{incoming,quarantine}`, `/var/lib/mail-console/archive`
  and, only if missing, the encryption key `/etc/mail-console/archive.key`.
  **Back up the key** separately from the archive.
* New dependency: `cryptography` (hash-pinned, ARM64 wheel).
* Nothing is captured until the Postfix change in
  [MAIL-CAPTURE.md](MAIL-CAPTURE.md) is reviewed and applied; that is a
  separate, manual step with its own verification and deactivation procedure.

## Rollback

```bash
sudo /usr/local/src/mail-console/deploy/rollback.sh              # code only
sudo /usr/local/src/mail-console/deploy/rollback.sh --restore-db # code and pre-update database
```

Use `--restore-db` when the newer release applied a migration the older code
does not understand (`mail-console check` reports the schema state).
Rolling back to a release without message capture is refused while Postfix
capture is applied; deactivate it first ([MAIL-CAPTURE.md](MAIL-CAPTURE.md)).

Rolling back from the EMAILS-UX-02 release without `--restore-db` is safe: the
older code ignores the new tables. It does not maintain the search index; when
you roll forward again, the new collector detects this at startup and
re-synchronises the index automatically (`sudo mail-console reindex` does the
same by hand). Events
ingested after the update are lost by `--restore-db`; they are re-read from the
log on the next start only while they are still in the current log file. The
replaced database is kept as `mail-console.sqlite3.rolled-back`.

## Uninstall

```bash
sudo /usr/local/src/mail-console/deploy/uninstall.sh          # keep config and database
sudo /usr/local/src/mail-console/deploy/uninstall.sh --purge  # also delete them and the user
```

Uninstall is refused while Postfix capture is applied; deactivate it first
([MAIL-CAPTURE.md](MAIL-CAPTURE.md)). It stops and removes only the two console
units, the wrapper and `/opt/mail-console`. Mail delivery is unaffected at every step; stopping the
console never affects Postfix.

## Operations

| Task | Command |
|---|---|
| Service logs | `journalctl -u mail-console-collector -u mail-console-web` |
| Collector status | Monitoring page → Collector, or `sudo mail-console check` |
| Reset a password | `sudo mail-console admin reset-password --username admin` (signs out all sessions) |
| Locked out by throttling | `sudo mail-console admin unlock` |
| Search index incomplete | `sudo mail-console reindex` |
| Archive health / integrity | `sudo mail-console archive status`, `sudo mail-console archive verify` |
| Lost 2FA device | `sudo mail-console admin totp-disable --username admin` |
| Apply retention now | `sudo mail-console purge` |
| Database backup | `sudo -u mailconsole sqlite3 /var/lib/mail-console/mail-console.sqlite3 ".backup /var/lib/mail-console/backups/manual.sqlite3"` (or copy while the services are stopped) |
| Re-ingest from scratch | stop both services, move the database away, `sudo mail-console migrate`, `sudo mail-console import --rotated`, recreate the admin, start |

If the Monitoring page shows "collector has not reported", check
`systemctl status mail-console-collector`; a collector outage never loses data
while the lines are still in the log files, because it resumes from its checkpoint.
