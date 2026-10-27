# Security

## Reporting

This repository is public. Report vulnerabilities privately to the repository
owner through GitHub's "Report a vulnerability" (Security tab), not in issues.

## Never commit

* Database files (`*.sqlite3`) – they contain real recipient addresses and SMTP responses.
* `/etc/mail-console/mail-console.env` or any `.env` file other than `.env.example`.
* Real log excerpts, email addresses, SMTP credentials, DKIM or TLS private keys, tokens.

Test fixtures use only reserved names (`example.com/.net/.org/.invalid`) and
documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24);
`tests/test_deploy.py` enforces this for tracked files.

## Design

| Area | Measure |
|---|---|
| Exposure | Binds to `127.0.0.1:8710` by default. The `Host` header must be loopback or listed in `MC_ALLOWED_HOSTS` (DNS-rebinding protection). The web unit may only talk to localhost (`IPAddressAllow=localhost`). Publish only via SSH tunnel or an HTTPS reverse proxy with network restrictions. |
| Two-factor | Optional TOTP (RFC 6238, SHA-1, 6 digits, 30 s, ±1 step) per administrator, enabled in Settings with password + code; codes cannot be replayed; a separate 5-minute pending-login token allows at most 5 attempts; recovery with `mail-console admin totp-disable`. |
| Accounts | No default credentials. The first administrator is created on the server with `mail-console admin create`. Passwords: 12+ characters, hashed with Argon2id (argon2-cffi; 64 MiB, t=3, p=4), rehashed automatically if parameters change. |
| Sessions | Random 256-bit tokens, stored only as SHA-256 hashes server-side; cookies `HttpOnly`, `SameSite=Strict`, `Secure` (default). 30-minute idle and 12-hour absolute expiry. Logout, password change and "sign out other sessions" revoke server-side. |
| CSRF | Per-session token on every state-changing form, a separate token for the login form, `Origin`/`Sec-Fetch-Site` checks on POST, and `SameSite=Strict`. |
| Brute force | Each attempt is recorded before the password is checked. Failed logins are throttled per client address (5 / 15 min), per username (10) and globally (50); an address that signed in successfully within 30 days is exempt from the username and global limits, so attackers cannot lock the owner out (`mail-console admin unlock` clears throttling). At most two Argon2 operations run at once (64 MiB each); extra requests get "busy". Responses do not reveal whether a username exists, and unknown users cost the same hash work. Attempted usernames are stored only as hashes. |
| Enumeration | Every page except `/login` and `/healthz` requires a session; unauthenticated requests are redirected without data. `/healthz` returns only `{"status":"ok"}`. |
| Browser | Strict CSP (`default-src 'none'`; scripts only from the console's own `/static/app.js`, no inline script; frames only from the console itself), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: same-origin`, `Cache-Control: no-store`, `noindex`. The page works fully without JavaScript. |
| Archived content | Complete, unredacted originals (owner requirement), readable only by administrators; every view and download is written to the audit log. HTML is served only from an authenticated route with `Content-Security-Policy: sandbox; default-src 'none'; img-src data:` inside `<iframe sandbox="">` (no scripts, forms, remote images, fonts or styles; links do not open); attachments are always `application/octet-stream` downloads with a sandbox CSP. Stored copies are encrypted with AES-256-GCM (key file `/etc/mail-console/archive.key`, back it up separately) and integrity-checked on every read. Capture runs as the dedicated user `mcarchive`, which can only write to the spool. |
| HTTPS | With `MC_TRUST_PROXY=true`, requests relayed by the proxy (carrying `X-Forwarded-For`) are refused unless `X-Forwarded-Proto: https`, and HSTS is sent; direct loopback access (SSH tunnel) keeps working. |
| Export | CSV export requires a session, respects the active filters, is capped at 50,000 rows and streamed. Cells starting with `= + - @`, tab or CR are prefixed with `'` (CSV/formula injection). Only the listed columns are exported (no SASL users, client IPs or raw log lines). |
| Secrets in logs | Passwords are never logged. Stored log lines pass through redaction of `password=`, `given password:`, `AUTH PLAIN/LOGIN <data>` and `Authorization:` values. Login attempts are recorded with the client address and only a hash of the attempted username. |
| Files | Database and WAL files `0600`, data directory `0750` (`mailconsole`), config `/etc/mail-console` `0750 root:mailconsole`, env file `0640`; services run with `UMask=0077`. Code under `/opt/mail-console` is root-owned and read-only to the service. |
| Privileges | Unprivileged `mailconsole` user, no capabilities, `NoNewPrivileges`, `ProtectSystem=strict`, system-call filter, private /tmp and devices. The collector has no network access (`AF_UNIX` only) and gets only the supplementary groups it needs to read: `adm` (syslog), `postdrop` (`postqueue -j`), `systemd-journal` (journald mode). |
| Mail stack | Read-only. The only commands run are `systemctl show` and `postqueue -j`. Nothing starts, stops, flushes or deletes queue entries, and no mail is sent. |
| Supply chain | Runtime dependencies are pinned with SHA-256 hashes and installed with `pip --require-hashes --only-binary=:all:`. No CDN assets. |

## Reverse proxy

If the console is published through a reverse proxy, restrict it by source
network (or VPN) and keep TLS on; see `deploy/nginx-example.conf`. Set
`MC_ALLOWED_HOSTS` to the public name and `MC_TRUST_PROXY=true` so login
throttling sees real client addresses. Deploying a proxy is a separate change
that requires its own approval.
