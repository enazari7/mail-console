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

Files: `deploy/postfix/master.cf.snippet`, `deploy/postfix/main.cf.snippet` and
`deploy/postfix/mailconsole_transport`. All commands are run as root on the mail
server, **only after review and approval**.

1. Preflight (read-only):
   ```bash
   sudo /opt/mail-console/current/deploy/capture-preflight.sh
   sudo postconf -n > /root/postfix-main.cf.before
   sudo cp /etc/postfix/master.cf /root/postfix-master.cf.before
   ```

2. Transport map for the archive address:
   ```bash
   sudo install -m 0644 /opt/mail-console/current/deploy/postfix/mailconsole_transport /etc/postfix/mailconsole_transport
   sudo postmap /etc/postfix/mailconsole_transport
   ```

3. `main.cf`. If `postconf -h transport_maps` is not empty, append to it instead:
   ```bash
   sudo postconf -e "transport_maps = hash:/etc/postfix/mailconsole_transport" \
                    "mailconsole-archive_destination_recipient_limit = 1"
   ```

4. `master.cf`: two new services. Copy the chroot column from the existing
   `cleanup` line (`postconf -M cleanup/unix`):
   ```bash
   sudo postconf -M "cleanup-archive/unix=cleanup-archive unix n - y - 0 cleanup"
   sudo postconf -P "cleanup-archive/unix/always_bcc=archive@mail-console.invalid"
   sudo postconf -M 'mailconsole-archive/unix=mailconsole-archive unix - n n - 4 pipe user=mcarchive argv=/opt/mail-console/current/bin/mc-capture --queue-id=${queue_id} --sender=${sender} --sasl-user=${sasl_username}'
   ```

5. The **only change to an existing service**: let authenticated submission use
   the archiving cleanup service.
   ```bash
   sudo postconf -P "submission/inet/cleanup_service_name=cleanup-archive"
   ```
   If BeastPing also submits on port 465, repeat this for `submissions/inet`
   (or `smtps/inet`).

6. Validate and activate. `reload` is graceful: no connections are dropped and
   queued mail is unaffected.
   ```bash
   sudo postfix check
   sudo postfix reload
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

| Situation | What happens |
|---|---|
| Spool disk has less than 1 GiB free, or a write fails | The capture program exits 75 (temporary failure). Postfix keeps **only the archive copy** in its deferred queue and retries with normal backoff. The console shows "Action needed" and an operational error for each deferral. |
| Problem persists beyond `maximal_queue_lifetime` (default 5 days) | Postfix gives up on the archive copy only. Because of NOTIFY=NONE nobody is notified, and that message is not archived. Fix disk space well before this. |
| Console services stopped | Captures accumulate in the spool and are ingested when the collector starts. |
| Archive limit (`MC_ARCHIVE_MAX_GB`) reached or disk low for the archive | The collector stops moving captures out of the spool and raises an alert. **Nothing is deleted before its retention period.** Raise the limit, add disk or lower retention. |
| Archive key missing or wrong | Encrypted copies cannot be read. The UI shows an error and `mail-console archive verify` fails. Captures still accumulate safely. |
| Crash during capture | A message counts as captured only after its `.json` is fsynced. Partial files are removed after an hour, and Postfix retries the delivery. |
| Crash during ingestion | Storing is idempotent: the next pass completes it, removes duplicates or reuses the stored blob. |
| Stored file altered or truncated | AES-GCM authentication fails: the UI shows an error instead of content, and `archive verify` reports it. |

## Deactivation (rollback of the Postfix change)

Deactivation takes effect immediately for new mail and does not affect
queued mail:

```bash
sudo postconf -PX submission/inet/cleanup_service_name
sudo postfix check && sudo postfix reload
```

To remove everything afterwards:

1. Remove the two `master.cf` services:
   ```bash
   sudo postconf -MX cleanup-archive/unix mailconsole-archive/unix
   ```
2. Restore `transport_maps` to its previous value from `/root/postfix-main.cf.before`.
3. Validate and reload:
   ```bash
   sudo postfix check && sudo postfix reload
   ```

Run this before ever uninstalling Mail Console, so that Postfix never tries to
run a missing capture program. Any archive copies still queued would then be
dropped silently (NOTIFY=NONE).

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

CI performs this full sequence against a real Postfix 3.8 on Ubuntu 24.04,
x86-64 and ARM64 (`capture-e2e` job). It includes deactivation, which shows
that new mail stops being captured while delivery continues. CI has no SASL
submission service, so there the archiving cleanup is attached to port 25.

## Storage, retention and limits

| Setting | Default | Meaning |
|---|---|---|
| `MC_ARCHIVE_DIR` | `/var/lib/mail-console/archive` | Content-addressed store (`<aa>/<bb>/<sha256>.enc`) |
| `MC_ARCHIVE_SPOOL` | `/var/spool/mail-console/incoming` | Capture spool (`mcarchive:mailconsole`, `2770`) |
| `MC_ARCHIVE_KEY_FILE` | `/etc/mail-console/archive.key` | 256-bit key; encryption is on when the file exists (`install.sh` creates it) |
| `MC_ARCHIVE_RETENTION_DAYS` | 90 | Overridden in Settings; archives older than this are deleted hourly |
| `MC_ARCHIVE_MAX_GB` | 10 | Hard limit for the store; reaching it pauses ingestion, never deletes early |
| `MC_ARCHIVE_WARN_PERCENT` | 80 | Monitoring turns to "Attention" |
| `MC_ARCHIVE_MIN_FREE_MB` | 2048 | Collector pauses ingestion below this free space |
| capture `--min-free-mb` | 1024 | Capture defers (Postfix retries) below this free space on the spool disk |

* **Sizing:** the console stores each message once, encrypted, at about its
  original size. For example, 5,000 messages a day at 30 KB average for 90
  days is about 13 GB, so raise `MC_ARCHIVE_MAX_GB` accordingly. The server
  has 38 GB; keep `maximal_queue_lifetime` worth of headroom for the Postfix
  queue.
* **Large messages:** large messages and attachments are streamed. Nothing
  loads a whole message into memory: tested with a 16 MiB message peaking
  under 8 MiB of Python memory.

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
  addresses, attachment names, the first 64 KiB of body text) in plaintext.

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
sudo postconf -e "sender_bcc_maps = hash:/etc/postfix/mailconsole_sender_bcc"
```

Trade-off: this is keyed by envelope sender, so it also archives any
`@beastping.com`-sender mail arriving on other paths, such as forged inbound
mail on port 25 that Postfix accepts for local delivery. Prefer the
submission-scoped proposal.
