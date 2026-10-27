#!/usr/bin/env bash
# Read-only checks before activating Mail Console message capture in Postfix.
# Changes nothing in Postfix; prints what it found and the exact proposal.
#   sudo ./deploy/capture-preflight.sh
set -uo pipefail
ARCHIVE=archive@mail-console.invalid
SPOOL=/var/spool/mail-console/incoming
ok() { printf 'ok    %s\n' "$*"; }
warn() { printf 'warn  %s\n' "$*"; WARN=1; }
fail() { printf 'FAIL  %s\n' "$*"; FAIL=1; }
WARN=0; FAIL=0
[ "$(id -u)" -eq 0 ] || { echo "run as root (read-only checks need postconf/runuser)"; exit 1; }
command -v postconf >/dev/null || { echo "postconf not found"; exit 1; }

ok "Postfix $(postconf -h mail_version)"
[ -x /usr/local/libexec/mail-console/mc-capture ] && ok "capture entry point installed" \
  || fail "/usr/local/libexec/mail-console/mc-capture missing (install or update Mail Console first)"
id -u mcarchive >/dev/null 2>&1 && ok "capture user mcarchive exists" || fail "user mcarchive missing (run install.sh)"
if [ -d "$SPOOL" ]; then
  ok "spool $SPOOL ($(stat -c '%a %U:%G' "$SPOOL"))"
  FREE=$(df -Pm "$SPOOL" | awk 'NR==2 {print $4}')
  [ "$FREE" -gt 4096 ] && ok "spool disk: ${FREE} MiB free" || warn "spool disk: only ${FREE} MiB free"
else
  fail "spool $SPOOL missing (run install.sh)"
fi
/usr/bin/python3 -c 'import sys; assert sys.version_info >= (3, 10)' && ok "system python3 $(/usr/bin/python3 -V 2>&1)" \
  || fail "/usr/bin/python3 >= 3.10 required by the capture program"

# Capture program dry run into a throw-away directory as the capture user.
TMP=$(mktemp -d); chown mcarchive "$TMP"
if printf 'Subject: preflight\n\npreflight\n' | runuser -u mcarchive -- /usr/local/libexec/mail-console/mc-capture \
     --queue-id=PREFLIGHT01 --sender=preflight@example.invalid --spool="$TMP" --min-free-mb=1; then
  [ -n "$(ls "$TMP"/*.json 2>/dev/null)" ] && ok "capture program works as mcarchive" || fail "capture wrote no files"
else
  fail "capture program exited with status $?"
fi
rm -rf "$TMP"

echo "--- current Postfix settings (read-only) ---"
SUBMISSION=$(postconf -M submission/inet 2>/dev/null)
if [ -n "$SUBMISSION" ]; then
  ok "submission service present: $(echo "$SUBMISSION" | tr -s ' ' | cut -c1-120)"
else
  warn "no 'submission' service in master.cf; adapt the proposal to the service BeastPing uses"
fi
[ -n "$(postconf -M cleanup-archive/unix 2>/dev/null)" ] && warn "cleanup-archive already defined" || ok "cleanup-archive not defined yet"
postconf -P submission/inet/cleanup_service_name 2>/dev/null | grep -q . \
  && warn "submission already overrides cleanup_service_name: $(postconf -P submission/inet/cleanup_service_name)" \
  || ok "submission uses the default cleanup service"
for p in always_bcc sender_bcc_maps recipient_bcc_maps transport_maps virtual_alias_maps canonical_maps \
         recipient_canonical_maps smtpd_milters non_smtpd_milters message_size_limit maximal_queue_lifetime; do
  printf '      %-26s = %s\n' "$p" "$(postconf -h "$p")"
done
for map in $(postconf -h virtual_alias_maps recipient_canonical_maps canonical_maps | tr ', ' '\n\n' | grep ':'); do
  if postmap -q "$ARCHIVE" "$map" >/dev/null 2>&1; then warn "$map rewrites $ARCHIVE; capture would not work"; fi
done
[ -n "$(postconf -h always_bcc)" ] && warn "global always_bcc is set; review interaction"

echo "--- proposal (not applied) ---"
echo "see deploy/postfix/*.snippet and docs/MAIL-CAPTURE.md"
[ "$FAIL" -eq 0 ] || exit 1
[ "$WARN" -eq 0 ] || exit 2
exit 0
