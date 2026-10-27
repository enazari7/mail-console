# Message capture and archive (MAIL-CONTENT-01)

Mail Console can keep a complete copy of every message BeastPing submits and
show it on the email's details page: subject, sender and recipients, the
plain-text and HTML bodies, inline images, attachments, all headers and the
original `.eml`.

**Status: proposal for review.** The Mail Console side (capture program,
spool, archive, UI) is installed by `install.sh`/`update.sh`, but nothing
reaches it until the Postfix change below is reviewed and applied by hand.
No Mail Console script edits Postfix.

## Architecture

```
BeastPing ──SMTP AUTH :587──▶ submission smtpd ──▶ cleanup-archive ──▶ queue ──▶ smtp ──▶ recipients
                                 (milters: Mailguard,   │ adds 1 hidden          │
                                  OpenDKIM — unchanged) │ recipient (always_bcc, └─▶ mailconsole-archive (pipe)
                                                        │ NOTIFY=NONE)               │ runs as user mcarchive
                                                                                     ▼
                                              /var/spool/mail-console/incoming/<ts>-<queue id>-<rand>.eml/.json
                                                                                     │ (collector, every 2 s)
                                                                                     ▼
                     /var/lib/mail-console/archive/<sha256>.enc  +  SQLite metadata, MIME index, search text
```

* **Where it hooks in:** a second Postfix `cleanup` service, used only by the
  authenticated submission service. It adds one envelope recipient,
  `archive@mail-console.invalid`, with Postfix's `always_bcc`. `transport_maps`
  routes that address to a `pipe` transport, which runs the capture program.
* **What is captured:** the message exactly as Postfix queued it, which is
  also what was delivered to the real recipients. That includes Postfix's own
  `Received:` header and the `DKIM-Signature` OpenDKIM added. `pipe(8)` emits
  LF line endings. The stored file is never modified afterwards. Header `Bcc:`
  lines are removed by Postfix before queueing, as for every recipient; Bcc
  recipients are still visible as SMTP envelope recipients in the delivery log.
* **What is not captured:**
  - inbound mail on port 25;
  - mail injected locally with `sendmail`;
  - Postfix's own bounce and delay notices;
  - anything sent before activation.
* **Correlation:** the pipe passes Postfix's `${queue_id}` to the capture
  program, so each copy is tied to one queue file.
  1. The copy is linked to the message lifetime whose log contains the
     delivery of this archive copy (`to=<archive@mail-console.invalid>`, same
     queue ID, within minutes of the capture).
  2. If that log line is not ingested yet, it falls back to the single lifetime
     of that queue ID that spans the capture time. When this is ambiguous
     (Queue ID reuse), the copy waits for more evidence.
  3. If the header `Message-ID` contradicts the `message-id=` Postfix logged
     for that queue file, the copy is **not linked**. It is listed under
     Monitoring → Message archive.

  Recipient address and timestamp are never used to correlate.
* **Requeues and content filters:** `postsuper -r` and after-queue content
  filters give the message a new queue ID. The archive copy travels with the
  queue file and is delivered under the new ID, so it links to the new
  lifetime. The details page already links old and new IDs ("Requeued as",
  "continues as").
* **Duplicates:** if Postfix redelivers the archive copy after a crash, the
  `(queue ID, SHA-256)` uniqueness and the content-addressed store keep a
  single copy.

### Why this mechanism

| Option | Verdict |
|---|---|
| `always_bcc` on a dedicated cleanup + `pipe` (this proposal) | Not in the SMTP acceptance path. The archive copy is an ordinary queued recipient: its failure is retried by Postfix and never affects the real recipients or notifies the sender. Scoped to authenticated submission. |
| `sender_bcc_maps` / `recipient_bcc_maps` in `main.cf` | Same delivery safety, no `master.cf` change. However, it is keyed by address, so a forged `@beastping.com` envelope sender on port 25 would also be archived. Kept as a fallback (see below). |
| A capture milter | Runs inside SMTP acceptance; a slow or crashed milter delays or rejects mail (`milter_default_action`). Rejected. |
| `smtpd_proxy_filter` / before-queue filter | In the acceptance path. Rejected. |
| Reading Postfix queue files | Needs root, races with delivery, files disappear. Rejected. |

## Exact proposed Postfix change

Production does not use a plain `submission/inet` service. It has two
named listeners, both with SMTP AUTH, TLS and the Mailguard/OpenDKIM milters:

| master.cf service | Purpose | Captured? |
|---|---|---|
| `91.107.182.219:submission/inet` | Public authenticated submission; **BeastPing connects here** | **Yes** |
| `127.0.0.1:submission/inet` | Loopback authenticated submission (local clients on the server) | **No** (by default) |

* **Why loopback is excluded:** BeastPing does not use the loopback listener.
  Local clients on the mail server (tests, tools) should not fill the
  archive. If BeastPing is ever moved to loopback, add it explicitly with
  `--listener 127.0.0.1:submission`.
* **CI coverage:** the end-to-end job checks both behaviours with this exact
  listener layout. Mail on the public listener is archived; mail on loopback
  is delivered and not archived.

The change is made by an operator tool, not by hand-typed `postconf` lines.
`deploy/capture_postfix.py` uses only the Python standard library and is
never called by install, update, rollback or uninstall. What it does:

1. **Discovers** every smtpd listener with `postconf -M` and `postconf -P`.
   It selects the single public (non-loopback), authenticated
   (`smtpd_sasl_auth_enable=yes`) submission listener. If there is none, or
   more than one, it **refuses** and asks for `--listener NAME`. It refuses a
   name that does not exist (it never creates a generic `submission`
   service), listeners without SMTP AUTH, and non-submission ports such as
   25, so inbound mail is never captured. It also refuses when an
   `always_bcc` is already in use, because that copy would otherwise be
   replaced, and when `trivial-rewrite` has its own `transport_maps`.
   `receive_override_options=no_address_mappings` (global, on the listener or
   on the cleanup service) is refused too, because it switches off
   `always_bcc` and nothing would be captured.
2. **Mirrors the cleanup service** the listener uses today. On Ubuntu that is
   `cleanup unix n - y - 0 cleanup`: chroot `y`, plus any `-o` options it
   has. `cleanup-archive` becomes an exact copy with only its name changed,
   plus `always_bcc=archive@mail-console.invalid`.
3. **Prepends** `hash:/etc/postfix/mailconsole_transport` to the existing
   `transport_maps`. Existing maps and their order, including the bounce
   collector's routing, are kept. The new map holds exactly one key, so it
   cannot shadow any other address.
4. Adds the `mailconsole-archive` pipe service and
   `mailconsole-archive_destination_recipient_limit = 1`.
5. Sets **only** `cleanup_service_name=cleanup-archive` on the selected
   listener. Every other option (TLS, SASL, restrictions,
   `smtpd_sender_login_maps`, `smtpd_milters`, `milter_macro_daemon_name`, …)
   stays as it is.
6. Records every previous value in `/etc/postfix/mailconsole-capture.json` and
   copies `main.cf`/`master.cf` to `/var/backups/mail-console-postfix/<time>/`
   **before** changing anything.
7. **Verifies** the result, and **automatically restores** everything if a
   check fails. The checks:
   - the listener's options equal the old ones plus `cleanup_service_name`;
   - no other listener uses `cleanup-archive`;
   - `cleanup-archive` has the same columns as its base;
   - the first `transport_maps` hit for `archive@mail-console.invalid` is
     `mailconsole-archive:`;
   - no `virtual_alias_maps` or canonical map rewrites the address;
   - `no_address_mappings` does not switch off `always_bcc`;
   - `mail-console.invalid` is not a local, virtual or relay domain.

     Together these mean the archive copy can only go to the internal pipe
     and never leaves the server.
8. Runs `postfix check`. It does **not** reload; the operator does.

### Safe activation commands (production, only after approval)

```bash
# 0. Console side installed or updated at the reviewed commit (creates mcarchive, spool, key, entry point)
cd /usr/local/src/mail-console && sudo ./deploy/update.sh

# 1. Read-only checks and the exact plan; must select 91.107.182.219:submission/inet
sudo /opt/mail-console/current/deploy/capture-preflight.sh
sudo python3 -I /opt/mail-console/current/deploy/capture_postfix.py plan

# 2. Apply. It prints the plan, asks for "yes", backs up, changes, verifies, and auto-restores on failure.
sudo python3 -I /opt/mail-console/current/deploy/capture_postfix.py apply

# 3. Activate (graceful: no connections dropped, queued mail unaffected)
sudo postfix reload
sudo python3 -I /opt/mail-console/current/deploy/capture_postfix.py status
```

If preflight cannot identify a single safe listener, it fails clearly (exit 1).
In that case, choose one explicitly:

```bash
sudo python3 -I /opt/mail-console/current/deploy/capture_postfix.py plan --listener 91.107.182.219:submission
```

The equivalent manual change, for review (not needed when using the tool):

```bash
sudo install -m 0644 /opt/mail-console/current/deploy/postfix/mailconsole_transport /etc/postfix/mailconsole_transport
sudo postmap /etc/postfix/mailconsole_transport
sudo postconf -e "transport_maps = hash:/etc/postfix/mailconsole_transport, $(postconf -h transport_maps)"
sudo postconf -e "mailconsole-archive_destination_recipient_limit = 1"
sudo postconf -M "cleanup-archive/unix=cleanup-archive unix n - y - 0 cleanup"      # columns copied from cleanup/unix
sudo postconf -P "cleanup-archive/unix/always_bcc=archive@mail-console.invalid"
sudo postconf -M 'mailconsole-archive/unix=mailconsole-archive unix - n n - 4 pipe user=mcarchive argv=/usr/local/libexec/mail-console/mc-capture --queue-id=${queue_id} --sender=${sender} --sasl-user=${sasl_username}'
sudo postconf -P "91.107.182.219:submission/inet/cleanup_service_name=cleanup-archive"
sudo postfix check && sudo postfix reload
```

### Effect on the current mail flow

| Aspect | Change |
|---|---|
| SMTP acceptance (587) | None: same listener, authentication, Mailguard and OpenDKIM milters, restrictions and TLS. The extra recipient is added after the SMTP conversation, inside cleanup. |
| Message content | Unchanged for the recipients. No header is added and `Bcc` handling is unchanged. |
| Envelope | One extra recipient per message, `archive@mail-console.invalid`. It is never visible to recipients or milters, and Postfix logs `nrcpt` one higher (the console compensates). |
| DSN / bounces | `always_bcc` uses NOTIFY=NONE: an archive failure never generates a bounce or delay notice to BeastPing's sender. |
| Delivery to real recipients | Independent. The queue file is removed only after the archive copy is delivered too, normally within a second. |
| Logs | One extra line per message: `to=<archive@mail-console.invalid>, relay=mailconsole-archive, status=sent`. The console shows it as "Copy delivered to the Mail Console archive" and never as a recipient. |
| Load | One short process per message (system Python, standard library only, ~30–60 ms) and the message size written once to the spool. At most 4 run concurrently. |
| Dependency on the console | None. The console web and collector services, its database and its virtualenv are not involved. Capture keeps working while they are stopped; the collector catches up from the spool. |

### Failure behaviour

Two rules guide it. Storage pressure must never hold mail in the Postfix
queue on a disk that is filling up. Nothing is dropped silently.

| Situation | What happens |
|---|---|
| Spool over `--max-spool-mb` (2 GiB), less than `--min-free-mb` (1 GiB) free, or ENOSPC while writing | The capture program reads and discards the message and writes a small `.skipped.json` marker, then exits 0. Postfix completes the queue file normally. The console records "archive copy not stored: <reason>" on that message, adds an operational error, and Monitoring shows **Action needed**. Real recipients are never affected. |
| Even the skip marker cannot be written (disk completely full) | The copy is lost, but not silently. Postfix logged it as delivered to the archive, and the console flags every such message without an archive or skip record ("delivered by Postfix but no stored copy"). |
| Unexpected error, bad arguments, missing spool, or the program was removed (rollback to a pre-capture release) | The wrapper `/usr/local/libexec/mail-console/mc-capture` maps every non-zero status to 75 (temporary failure). Postfix keeps only the archive copy deferred and retries; nobody is notified (NOTIFY=NONE). Postfix logs each deferral, and the console reports them. After `maximal_queue_lifetime` (default 5 days) Postfix drops only that copy. |
| Console services stopped | Captures accumulate in the spool, up to the 2 GiB cap, and are ingested when the collector starts. |
| Archive limit (`MC_ARCHIVE_MAX_GB`) reached, or the archive disk is low | The collector stops moving captures out of the spool and raises an alert; **nothing is deleted before its retention period**. If this is ignored until the spool cap is reached, new copies are skipped as above. Monitoring warns from 80 % (`MC_ARCHIVE_WARN_PERCENT`). |
| Encryption key missing while `MC_ARCHIVE_ENCRYPTION=required` (default) | Nothing is stored in plaintext. Captures wait in the spool and an alert is raised. |
| Hostile or malformed MIME | The raw original is still archived and downloadable; the parse problem is recorded on the archive. A capture that cannot be trusted at all (invalid metadata, symlink, hash mismatch) is moved to `/var/spool/mail-console/quarantine` and never blocks other captures. |
| Crash during capture | A message counts as captured only after its `.json` is fsynced. Partial files are removed after an hour, and Postfix retries the delivery. |
| Crash during ingestion | Archive rows are committed with full fsync before the spool files are removed. The next pass completes the work, de-duplicates it or reuses the verified blob. |
| Stored file altered or truncated | AES-GCM authentication fails: the UI shows an error instead of content, and `archive verify` reports it. |

## Deactivation (rollback of the Postfix change)

Deactivation has two phases. This way copies already in the queue still reach
the archive transport, and never follow a default or relay route:

```bash
# Phase 1: listeners get back their exact previous cleanup_service_name. No new copies after the reload.
sudo python3 -I /opt/mail-console/current/deploy/capture_postfix.py deactivate
sudo postfix reload

# Wait until no queued message still carries the archive copy (normally immediately)
sudo python3 -I /opt/mail-console/current/deploy/capture_postfix.py status

# Phase 2: remove the archive route, the two services and the map
sudo python3 -I /opt/mail-console/current/deploy/capture_postfix.py deactivate --finish
sudo postfix reload
```

* **`--finish` refuses**, and changes nothing, while any of these is true.
  Run it again later; there is no option to skip the checks.
  - `postqueue -j` shows a queued message that still carries the archive
    recipient. Removing the route then would send that copy to the default
    route or a relayhost.
  - A running Postfix process still uses `cleanup-archive`: `postfix reload`
    was not run after phase 1, or an SMTP session from before the reload is
    still open.
  - Any other `master.cf` service or `main.cf` parameter still refers to
    `cleanup-archive` or `mailconsole-archive`, for example a listener copied
    from the captured one after `apply`. Removing the services would make that
    listener temp-fail all mail. Phase 1 already warns about these.
* **Only Mail Console's own changes are removed**, from the *current*
  configuration:
  - the `mailconsole_transport` entry is removed from `transport_maps`; maps
    added by an administrator after `apply` (for example for the bounce
    collector) stay;
  - the recipient limit is reset only if `main.cf` still has Mail Console's
    value. It is read from the file itself, because `postconf` hides this
    parameter once the pipe service is gone;
  - if an administrator removed the other maps after `apply`, they are not
    brought back; other table references (including `inline:{…}`) are kept
    as written;
  - a map file that existed before `apply` is written back.
* **Manual listener edits:** if the listener was edited by hand in between,
  `deactivate` restores `cleanup_service_name`, reports the other edits as
  warnings and leaves them alone.
* **Tested exact restore:** without later edits the result is identical to
  the pre-`apply` configuration. CI holds one archive copy in the queue,
  checks that `--finish` refuses, delivers the copy and finishes. It then
  compares `postconf -n`, `postconf -M`, `postconf -P` and `main.cf` (byte for
  byte) with the state before `apply`, and checks that `postconf` prints no
  warning about a leftover parameter.

Do this before uninstalling Mail Console or rolling back to a release
without capture. While `/etc/postfix/mailconsole-capture.json` exists (capture
applied, or only phase 1 done):

- `uninstall.sh` refuses, and `rollback.sh` refuses to go back to a release
  without capture. `--force` overrides this.
- If forced, a normal uninstall keeps the wrapper
  `/usr/local/libexec/mail-console/mc-capture`, which defers archive copies
  (exit 75) instead of losing them; `--purge` removes the wrapper.

## Verification after activation

1. Trigger a normal BeastPing email, for example a password reset to a mailbox you own.
2. Check the log:
   ```bash
   grep archive@mail-console.invalid /var/log/syslog | tail -2
   ```
   Expect `status=sent (delivered via mailconsole-archive service)`.
3. In Mail Console, open the email. *Message content* shows the subject and
   body, the HTML tab renders, attachments and *Download .eml* work, and the
   delivery timeline still lists the real recipients.
4. Check archive health:
   ```bash
   sudo mail-console archive status
   sudo mail-console archive verify
   ```
5. Confirm the queue drains as before:
   ```bash
   postqueue -p
   ```

CI runs this whole sequence on x86-64 and ARM64 (`capture-e2e` job). It uses
a real Postfix 3.8 on Ubuntu 24.04 with the production listener layout: a
public and a loopback named submission listener, Dovecot SASL, required TLS
and milter options. It checks that:

- the public listener is archived and the loopback listener is not;
- a broken capture defers only the archive copy, with no bounce;
- deactivation restores the configuration exactly.

## Storage, retention and limits

| Setting | Default | Meaning |
|---|---|---|
| `MC_ARCHIVE_DIR` | `/var/lib/mail-console/archive` | Content-addressed store (`<aa>/<bb>/<sha256>.enc`) |
| `MC_ARCHIVE_SPOOL` | `/var/spool/mail-console/incoming` | Capture spool (`mcarchive:mailconsole`, `2770`) |
| `MC_ARCHIVE_KEY_FILE` | `/etc/mail-console/archive.key` | 256-bit key; encryption is on when the file exists (`install.sh` creates it) |
| `MC_ARCHIVE_RETENTION_DAYS` | 90 | Overridden in Settings; archives older than this are deleted hourly |
| `MC_ARCHIVE_MAX_GB` | 8 | Hard limit for the store; reaching it pauses ingestion, never deletes early |
| `MC_ARCHIVE_WARN_PERCENT` | 80 | Monitoring turns to "Attention" |
| `MC_ARCHIVE_MIN_FREE_MB` | 4096 | Collector pauses ingestion below this free space |
| capture `--min-free-mb` | 1024 | Below this free space the copy is skipped with a recorded marker |
| capture `--max-spool-mb` | 2048 | Spool size at which copies are skipped with a recorded marker |
| `MC_ARCHIVE_ENCRYPTION` | `required` | `required`: never store plaintext; `off`: allow storing without a key |
| `MC_ARCHIVE_INDEX_BODY_BYTES` | 2048 | Characters of body text added to the search index per message (0 = none) |

* **Sizing:** the console stores each message once, encrypted, at about its
  original size. For example, 5,000 messages a day at 30 KB average for 90
  days is about 13 GB. That is more than the 8 GB budget recommended below for
  this 38 GB server, so shorten archive retention instead. See *Disk capacity*
  below.
* **Large messages:** large messages and attachments are streamed. Nothing
  loads a whole message into memory: tested with a 16 MiB message peaking
  under 8 MiB of Python memory.

## Disk capacity on the 38 GB ARM64 server

Everything shares one 38 GB filesystem: the OS, the logs, the Postfix
queue, the console database, the archive and the capture spool.

| Consumer | Typical size | Notes |
|---|---|---|
| Ubuntu 24.04, packages, BeastPing app, caches | 6–8 GB | measure with `df -h /` before activation |
| `/var/log` (rsyslog rotation, journald) | 1–3 GB | `journalctl --disk-usage`; cap with `SystemMaxUse=` if large |
| **Postfix queue headroom** | **≥ 4 GB kept free** (deferred archive copies hold their whole queue file: 20,000/day × 40 KB × 5 days ≈ 4 GB in the worst case) | covers a destination outage (deferred mail) and Postfix's own free-space check: smtpd defers new mail when free space drops below `queue_minfree` (at least 1.5 × `message_size_limit`) |
| Capture spool | ≤ 2 GB (`--max-spool-mb`) | normally empty; fills only while the console is not ingesting |
| Console database | `MC_MAX_DB_MB` | ~5 KB per logged message + ~10 KB per archived message (search index of 2,048 body chars) |
| Archive store | `MC_ARCHIVE_MAX_GB` | ≈ message size per archived message (encryption adds 0.03 %) |

* **Archive size per day** ≈ messages per day × average size. Measure the
  real values on the server before activation:
  ```bash
  # submitted messages per day and their average size, from Postfix logs
  sudo grep -h 'postfix/qmgr.*nrcpt=' /var/log/syslog | grep -c . 
  sudo grep -h 'postfix/qmgr.*nrcpt=' /var/log/syslog | sed -E 's/.*size=([0-9]+).*/\1/' \
    | awk '{s+=$1; n++} END {printf "%d messages, average %.1f KB\n", n, s/n/1024}'
  ```
* **Recommended budget** (these are the defaults of this release; an existing
  `/etc/mail-console/mail-console.env` keeps its own values, so set them there).
  About 12–14 GB in total for Mail Console. From 38 GB that leaves about 24 GB.
  The OS and packages (6–8 GB) and logs (1–3 GB) use part of it, so roughly
  13–17 GB stays free as Postfix queue headroom and safety margin. Note that
  ext4 reserves 5 % (about 1.9 GB) for root, which the `mcarchive` and
  `postfix` users cannot use.
  - `MC_ARCHIVE_MAX_GB=8`;
  - `MC_MAX_DB_MB=3072`;
  - spool cap 2 GB;
  - capture `--min-free-mb=1024`;
  - `MC_ARCHIVE_MIN_FREE_MB=4096`, so the collector stops filling the disk
    while 4 GB are still free for Postfix.
* **Retention by volume** (average 40 KB transactional message):

  | Messages/day | Archive per day | Archive retention that fits 8 GB | Log retention that fits 3 GB DB |
  |---|---|---|---|
  | 1,000 | 40 MB | 180 days | 90 days or more |
  | 5,000 | 200 MB | 30–40 days | ~40 days |
  | 20,000 | 800 MB | 7–10 days | 10–14 days (or `MC_ARCHIVE_INDEX_BODY_BYTES=512`) |

  Database estimate: about 5 KB per logged message, plus about 10 KB per
  archived message while its search index is kept. At 5,000 messages a day,
  40 days of history with a 35-day archive is about 2.8 GB.

* **Alerts:**
  - Monitoring turns **Attention** at 80 % of `MC_ARCHIVE_MAX_GB` and
    **Action needed** at the limit.
  - Nothing is deleted before its retention period. At the limit, captures
    wait, and then are skipped with a record.
  - Plan for the first alert by shortening archive retention in Settings
    (applied within an hour) or adding disk.
* **Monthly check:**
  ```bash
  df -h /
  sudo du -sh /var/spool/postfix /var/lib/mail-console /var/spool/mail-console
  sudo mail-console archive status
  ```

## Encryption at rest

* **Cipher:** AES-256-GCM over 64 KiB chunks. The per-file key is derived from
  the master key and a random salt. Every chunk is authenticated, and its
  position and the end of file are bound in, so tampering, reordering and
  truncation are detected.
* **Key:** `/etc/mail-console/archive.key` (`root:mailconsole 0640`).
  - It protects copies of the archive that leave the machine, such as backups
    or a detached disk. It does not protect against someone with root on the
    running server.
  - **Back the key up separately from the archive:** without it the archive is
    unreadable, and with it anyone holding a copy of the archive can read it.
- The short-lived spool files are plaintext (`0640`, readable only by the
  console group). They normally exist for under two seconds.
- The SQLite database (`0600`) contains searchable text (subject, header
  addresses, attachment names, the first 2,048 characters of body text) in plaintext.
  When `MC_MAX_DB_MB` is reached, the oldest of these index entries are
  dropped first; the archived messages stay viewable.

## Backup and restore

```bash
# Backup (no downtime needed): database snapshot, then the store, key stored separately.
sudo -u mailconsole /opt/mail-console/current/venv/bin/python - <<'PY'
import sqlite3; s = sqlite3.connect("/var/lib/mail-console/mail-console.sqlite3")
d = sqlite3.connect("/var/lib/mail-console/backups/manual.sqlite3"); s.backup(d); d.close()
PY
sudo tar -C /var/lib/mail-console -czf /root/mail-console-archive.tgz archive backups/manual.sqlite3
sudo cp /etc/mail-console/archive.key /root/archive.key.backup   # keep elsewhere!

# Restore
sudo systemctl stop mail-console-collector mail-console-web
sudo tar -C /var/lib/mail-console -xzf /root/mail-console-archive.tgz
sudo mv /var/lib/mail-console/backups/manual.sqlite3 /var/lib/mail-console/mail-console.sqlite3
sudo chown -R mailconsole:mailconsole /var/lib/mail-console
sudo install -m 0640 -o root -g mailconsole /root/archive.key.backup /etc/mail-console/archive.key
sudo systemctl start mail-console-collector mail-console-web
sudo mail-console archive verify
```

## Access, privacy and audit

* **Access:** archived content, attachments and `.eml` downloads require an
  administrator session. Two-factor authentication (TOTP) is available in
  Settings.
* **Audit log:** every content view, HTML preview, attachment download and
  `.eml` download is recorded with user, client address and time, together
  with sign-ins, failed sign-ins and 2FA and retention changes. See the
  *Audit log* page.
* **HTML preview isolation:**
  - The preview is served with `Content-Security-Policy: sandbox;
    default-src 'none'; img-src data:` and shown in `<iframe sandbox="">`.
  - Scripts, forms, plugins, remote images, fonts and styles are blocked,
    which also stops tracking pixels. Links do not open.
  - Embedded `cid:` images are inlined as `data:` URIs for display only.
* **Attachments:** always downloaded as `application/octet-stream` with an
  attachment disposition and a sandbox CSP, never rendered in the console's
  origin.
* **No redaction:** the archived original is complete and unredacted, by the
  owner's requirement. It contains verification codes and reset links, so
  treat the archive, its key and its backups as sensitive as the mailboxes
  themselves.

## Fallback: sender-scoped capture without touching master.cf's submission entry

If the submission service must stay byte-for-byte unchanged, step 5 can be
replaced. Keep steps 2–4 but drop the `cleanup-archive` service and step 5,
then add:

```bash
echo '@beastping.com archive@mail-console.invalid' | sudo tee /etc/postfix/mailconsole_sender_bcc
sudo postmap /etc/postfix/mailconsole_sender_bcc
# prepend, keeping an existing sender_bcc_maps (first match wins: check it has no entry for @beastping.com senders)
CUR="$(postconf -h sender_bcc_maps)"
sudo postconf -e "sender_bcc_maps = hash:/etc/postfix/mailconsole_sender_bcc${CUR:+, $CUR}"
```

Trade-off: this is keyed by envelope sender, so it also archives any
`@beastping.com`-sender mail arriving on other paths, such as forged inbound
mail on port 25 that Postfix accepts for local delivery. Prefer the
submission-scoped proposal.
