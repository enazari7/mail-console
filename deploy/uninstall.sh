#!/usr/bin/env bash
# Remove BeastPing Mail Console.
#   sudo ./deploy/uninstall.sh          # remove code and units; keep config and data
#   sudo ./deploy/uninstall.sh --purge  # also delete config, database and the service user
#   --force: continue although Postfix capture is still applied
# Mail delivery services are not touched.
set -euo pipefail
CAPTURE_STATE=/etc/postfix/mailconsole-capture.json
PURGE=0
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    --force) FORCE=1 ;;
    *) echo "unknown option: $arg" >&2; exit 1 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
if [ -e "$CAPTURE_STATE" ] && [ "$FORCE" -eq 0 ]; then
  echo "refusing: Postfix capture is still applied ($CAPTURE_STATE). Archive copies would be deferred" >&2
  echo "          (or, with --purge, lost). Deactivate it first (docs/MAIL-CAPTURE.md, both phases)," >&2
  echo "          or pass --force. Nothing changed." >&2
  exit 1
fi

for unit in mail-console-web.service mail-console-collector.service; do
  systemctl disable --now "$unit" 2>/dev/null || true
  rm -f "/etc/systemd/system/$unit"
done
rm -rf /etc/systemd/system/mail-console-collector.service.d
systemctl daemon-reload
rm -f /usr/local/sbin/mail-console
rm -rf /opt/mail-console
echo "==> removed code, units and wrapper"

if [ "$PURGE" -eq 1 ]; then
  rm -rf /etc/mail-console /var/lib/mail-console /var/spool/mail-console
  rm -rf /usr/local/libexec/mail-console
  if id -u mcarchive >/dev/null 2>&1; then userdel mcarchive; fi
  getent group mcarchive >/dev/null && groupdel mcarchive || true
  if id -u mailconsole >/dev/null 2>&1; then userdel mailconsole; fi
  getent group mailconsole >/dev/null && groupdel mailconsole || true
  echo "==> purged configuration, database and the mailconsole user"
else
  echo "==> kept /etc/mail-console, /var/lib/mail-console and /var/spool/mail-console (use --purge to delete)"
  echo "    The capture entry point /usr/local/libexec/mail-console/mc-capture was kept: while Postfix
    capture is active it now defers archive copies (exit 75) instead of losing them.
    Deactivate capture in Postfix first (docs/MAIL-CAPTURE.md), then use --purge to remove it."
fi
