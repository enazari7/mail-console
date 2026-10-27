# Deployment and acceptance checklist

Record the commit SHA, date and operator. Every item is verified on the server
after installation; none of them changes the mail stack.

## Before installation

- [ ] Reviewed commit SHA: `________`
- [ ] Postfix, Dovecot, OpenDKIM, Mailguard healthy: `systemctl is-active postfix@- dovecot opendkim <mailguard unit>`
- [ ] Baseline queue size noted: `postqueue -j | wc -l` = `____`
- [ ] Mailguard unit name confirmed for `MC_MONITOR_UNITS`
- [ ] Free disk space > 2 GB on `/var/lib`: `df -h /var/lib`

## Installation

- [ ] `sudo ./deploy/install.sh --no-start` succeeded
- [ ] `/etc/mail-console/mail-console.env` reviewed; `MC_BIND=127.0.0.1`
- [ ] `sudo mail-console check`: log readable, schema up to date, DB mode 600, data dir 750 or stricter
- [ ] `sudo mail-console parse-check /var/log/syslog`: delivery statuses match `grep -c 'status=sent' /var/log/syslog` (and deferred/bounced)
- [ ] Optional: `sudo mail-console import --rotated` completed
- [ ] Administrator created; no default password exists
- [ ] Both console services active: `systemctl is-active mail-console-collector mail-console-web`
- [ ] Listening on loopback only: `ss -ltnp | grep 8710` shows `127.0.0.1:8710`

## Definition of done

- [ ] **Login**: administrator can sign in through the SSH tunnel
- [ ] **History**: previously logged emails appear on Emails and Overview
- [ ] **Live**: a new email sent by the normal BeastPing application flow (not by
      the console) appears within a few seconds, without manual processing
- [ ] **Search**: searching the recipient and the Queue ID of that email returns
      it; the detail timeline matches `grep <QUEUEID> /var/log/syslog`
- [ ] **Statuses**: a `status=sent` line shows as Accepted (with the "not inbox
      placement" note); any deferred/bounced/rejected line in the logs shows with
      its DSN and remote SMTP response
- [ ] **Charts and pagination**: Overview charts render for 24h/7d/30d; Emails
      pagination moves between pages
- [ ] **Monitoring**: unit states for Postfix, Mailguard, OpenDKIM, Dovecot are
      correct; queue count matches `postqueue -j | wc -l`
- [ ] **Restart**: `sudo systemctl restart mail-console-collector mail-console-web`;
      history still present, no duplicate rows
- [ ] **Security**: anonymous `curl -si http://127.0.0.1:8710/emails?q=example`
      returns `303` to `/login` without data; 6 wrong passwords produce "Too many
      failed attempts"
- [ ] **ARM64**: `uname -m` is `aarch64`; no Docker installed or used
- [ ] **Mail unaffected**: mail services still active, uptime/PIDs unchanged
      (`systemctl show -p MainPID,ActiveEnterTimestamp postfix@- dovecot opendkim`),
      queue size back to baseline, a production test email still reaches Gmail/Yahoo
- [ ] **No secrets committed**: repository contains no `.env`, database or key files
      (`git ls-files | grep -E '\.(sqlite3|env|pem|key)$'` is empty)
- [ ] Automated smoke test passes:
      `printf '%s\n' '<pw>' | python3 /opt/mail-console/current/deploy/smoke_test.py --username admin --password-stdin --expect <QUEUEID>`

## Rollback readiness

- [ ] `/opt/mail-console/previous` exists after the first update, or uninstall is the fallback
- [ ] Database backups present in `/var/lib/mail-console/backups/` after updates

Sign-off: ______________________  Date: __________
