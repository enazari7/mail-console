#!/usr/bin/env bash
# Roll back to the previous release.
#   sudo ./deploy/rollback.sh               # switch code back, keep the database
#   sudo ./deploy/rollback.sh --restore-db  # also restore the pre-update database backup
# Only the mail-console services are stopped/started.
set -euo pipefail
PREFIX=/opt/mail-console
DATA_DIR=/var/lib/mail-console
RESTORE_DB=0
[ "${1:-}" = "--restore-db" ] && RESTORE_DB=1
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

CURRENT=$(readlink "$PREFIX/current")
TARGET=$(cat "$PREFIX/previous" 2>/dev/null || true)
[ -n "$TARGET" ] && [ -d "$PREFIX/$TARGET" ] || { echo "no previous release recorded" >&2; exit 1; }
echo "==> rolling back: $CURRENT -> $TARGET"

systemctl stop mail-console-web.service mail-console-collector.service
if [ "$RESTORE_DB" -eq 1 ]; then
  BACKUP="$DATA_DIR/backups/pre-$(basename "$CURRENT").sqlite3"
  [ -f "$BACKUP" ] || { echo "backup $BACKUP not found; database left unchanged" >&2; exit 1; }
  DB=$(set -a; . /etc/mail-console/mail-console.env; set +a; echo "${MC_DB_PATH:-${MC_DATA_DIR:-$DATA_DIR}/mail-console.sqlite3}")
  echo "==> restoring $BACKUP -> $DB (current database kept as $DB.rolled-back)"
  mv "$DB" "$DB.rolled-back"
  rm -f "$DB-wal" "$DB-shm"
  install -m 0600 -o mailconsole -g mailconsole "$BACKUP" "$DB"
fi
ln -sfn "$TARGET" "$PREFIX/current.new"
mv -T "$PREFIX/current.new" "$PREFIX/current"
echo "$CURRENT" > "$PREFIX/previous"
install -m 0644 "$PREFIX/current/deploy/systemd/mail-console-web.service" /etc/systemd/system/
install -m 0644 "$PREFIX/current/deploy/systemd/mail-console-collector.service" /etc/systemd/system/
systemctl daemon-reload
systemctl start mail-console-collector.service mail-console-web.service
systemctl --no-pager --lines=0 status mail-console-web.service mail-console-collector.service || true
echo "==> now running $(readlink "$PREFIX/current")"
