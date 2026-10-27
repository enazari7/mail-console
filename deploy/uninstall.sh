#!/usr/bin/env bash
# Remove BeastPing Mail Console.
#   sudo ./deploy/uninstall.sh          # remove code and units; keep config and data
#   sudo ./deploy/uninstall.sh --purge  # also delete config, database and the service user
# Mail delivery services are not touched.
set -euo pipefail
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

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
  rm -rf /etc/mail-console /var/lib/mail-console
  if id -u mailconsole >/dev/null 2>&1; then userdel mailconsole; fi
  getent group mailconsole >/dev/null && groupdel mailconsole || true
  echo "==> purged configuration, database and the mailconsole user"
else
  echo "==> kept /etc/mail-console and /var/lib/mail-console (use --purge to delete)"
fi
