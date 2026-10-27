#!/usr/bin/env bash
# Install or update BeastPing Mail Console from this source checkout.
#
#   sudo ./deploy/install.sh            # install or update, then (re)start the console services
#   sudo ./deploy/install.sh --no-start # install files only
#
# Scope: this script creates the 'mailconsole' system user and touches only
#   /opt/mail-console, /etc/mail-console, /var/lib/mail-console,
#   /usr/local/sbin/mail-console and the two mail-console-*.service units.
# It never modifies, restarts or reloads Postfix, Dovecot, OpenDKIM, Mailguard,
# DNS, firewall rules or any mail spool/bounce database.
set -euo pipefail

PREFIX=/opt/mail-console
ETC_DIR=/etc/mail-console
DATA_DIR=/var/lib/mail-console
SERVICE_USER=mailconsole
UNIT_DIR=/etc/systemd/system
UNITS=(mail-console-collector.service mail-console-web.service)
KEEP_RELEASES=3
PYTHON=${PYTHON:-python3.12}
START=1

for arg in "$@"; do
  case "$arg" in
    --no-start) START=0 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- preflight ---------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
[ -f "$SRC/mailconsole/__init__.py" ] && [ -f "$SRC/requirements.lock" ] || die "run from a mail-console checkout"
command -v systemctl >/dev/null || die "systemd is required"
command -v "$PYTHON" >/dev/null || die "$PYTHON not found (apt install python3.12)"
"$PYTHON" -c 'import sys; assert sys.version_info >= (3, 12)' || die "Python 3.12+ required"
"$PYTHON" -c 'import venv, ensurepip' 2>/dev/null || die "python venv support missing (apt install python3.12-venv)"
ARCH=$(uname -m)
case "$ARCH" in
  aarch64|arm64|x86_64) log "architecture: $ARCH" ;;
  *) log "warning: untested architecture $ARCH" ;;
esac

VERSION=$("$PYTHON" -c "import re,sys; print(re.search(r'__version__ = \"([^\"]+)\"', open(sys.argv[1]).read()).group(1))" "$SRC/mailconsole/__init__.py")
REV=$(git -C "$SRC" rev-parse --short=12 HEAD 2>/dev/null || echo nogit)
RELEASE="$(date -u +%Y%m%dT%H%M%SZ)-$VERSION-$REV"
DEST="$PREFIX/releases/$RELEASE"

# --- user and directories ----------------------------------------------------
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  log "creating system user $SERVICE_USER"
  useradd --system --user-group --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin \
    --comment "BeastPing Mail Console" "$SERVICE_USER"
fi
install -d -m 0755 -o root -g root "$PREFIX" "$PREFIX/releases"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR/backups"
install -d -m 0750 -o root -g "$SERVICE_USER" "$ETC_DIR"
if [ ! -f "$ETC_DIR/mail-console.env" ]; then
  log "creating $ETC_DIR/mail-console.env from .env.example (review it)"
  install -m 0640 -o root -g "$SERVICE_USER" "$SRC/.env.example" "$ETC_DIR/mail-console.env"
else
  chown root:"$SERVICE_USER" "$ETC_DIR/mail-console.env"
  chmod 0640 "$ETC_DIR/mail-console.env"
fi

# --- message capture: user, spool, archive, key ------------------------------
# Only prepares the console side. Postfix is NOT changed here; activating
# capture is a separate, reviewed step (docs/MAIL-CAPTURE.md).
CAPTURE_USER=mcarchive
SPOOL_ROOT=/var/spool/mail-console
if ! id -u "$CAPTURE_USER" >/dev/null 2>&1; then
  log "creating system user $CAPTURE_USER (runs only the Postfix capture program)"
  useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin \
    --comment "Mail Console message capture" "$CAPTURE_USER"
fi
install -d -m 0755 -o root -g root "$SPOOL_ROOT"
# setgid directory: captured files belong to group mailconsole (0640), so the
# collector can read and remove them; the capture user cannot read anything else.
install -d -m 2770 -o "$CAPTURE_USER" -g "$SERVICE_USER" "$SPOOL_ROOT/incoming"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$SPOOL_ROOT/quarantine" "$DATA_DIR/archive"
if [ ! -f "$ETC_DIR/archive.key" ]; then
  log "generating archive encryption key $ETC_DIR/archive.key -- back it up separately from the archive"
  ( umask 077; "$PYTHON" -c 'import secrets; print(secrets.token_hex(32))' > "$ETC_DIR/archive.key" )
fi
chown root:"$SERVICE_USER" "$ETC_DIR/archive.key"
chmod 0640 "$ETC_DIR/archive.key"

# --- release -----------------------------------------------------------------
log "installing release $RELEASE"
install -d -m 0755 "$DEST"
cp -r "$SRC/mailconsole" "$DEST/"
cp "$SRC/requirements.lock" "$SRC/pyproject.toml" "$SRC/README.md" "$DEST/"
cp -r "$SRC/deploy" "$DEST/"
install -d -m 0755 "$DEST/bin"
install -m 0755 "$SRC/deploy/bin/mc-capture" "$DEST/bin/mc-capture"
find "$DEST" -name '__pycache__' -prune -exec rm -rf {} +
"$PYTHON" -m venv "$DEST/venv"
"$DEST/venv/bin/python" -m pip install --quiet --disable-pip-version-check --no-cache-dir \
  --require-hashes --only-binary=:all: -r "$DEST/requirements.lock"
"$DEST/venv/bin/python" -m compileall -q "$DEST/mailconsole" >/dev/null
echo "$RELEASE" > "$DEST/RELEASE"
chown -R root:root "$DEST"
chmod -R go-w "$DEST"

run_as_service() {
  # Supplementary groups mirror the collector unit so 'import' and 'check' can read logs.
  local groups=()
  for g in adm postdrop systemd-journal; do getent group "$g" >/dev/null && groups+=(-G "$g"); done
  runuser -u "$SERVICE_USER" -g "$SERVICE_USER" "${groups[@]}" -- \
    env PYTHONPATH="$1" PYTHONDONTWRITEBYTECODE=1 MC_ENV_FILE="$ETC_DIR/mail-console.env" \
    "$1/venv/bin/python" -m mailconsole "${@:2}"
}

# --- stop the console (never the mail services) during backup and migration --
# The running (older) release must not write to the database while the new
# schema and search index are being built; it resumes from its checkpoint.
STOPPED=()
for unit in "${UNITS[@]}"; do
  if systemctl is-active --quiet "$unit"; then
    STOPPED+=("$unit")
  fi
done
if [ "${#STOPPED[@]}" -gt 0 ]; then
  log "stopping ${STOPPED[*]} for the database upgrade"
  systemctl stop "${STOPPED[@]}"
fi
restart_previous() {
  if [ "${#STOPPED[@]}" -gt 0 ] && [ -z "${SWITCHED:-}" ]; then
    echo "==> install failed before switching releases; restarting the previous release" >&2
    systemctl start "${STOPPED[@]}" || true
  fi
}
trap restart_previous EXIT

# --- database backup and migration -----------------------------------------
DB=$(set -a; . "$ETC_DIR/mail-console.env"; set +a; echo "${MC_DB_PATH:-${MC_DATA_DIR:-$DATA_DIR}/mail-console.sqlite3}")
if [ -f "$DB" ]; then
  BACKUP="$DATA_DIR/backups/pre-$RELEASE.sqlite3"
  log "backing up database to $BACKUP"
  runuser -u "$SERVICE_USER" -- "$DEST/venv/bin/python" -c \
    'import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d); d.close()' \
    "$DB" "$BACKUP"
  chmod 0600 "$BACKUP"
  ls -1t "$DATA_DIR"/backups/pre-*.sqlite3 2>/dev/null | tail -n +6 | xargs -r rm -f
fi
log "applying database migrations"
run_as_service "$DEST" migrate

# --- switch release atomically ---------------------------------------------
PREVIOUS=$(readlink "$PREFIX/current" 2>/dev/null || true)
ln -sfn "releases/$RELEASE" "$PREFIX/current.new"
mv -T "$PREFIX/current.new" "$PREFIX/current"
SWITCHED=1
[ -n "$PREVIOUS" ] && echo "$PREVIOUS" > "$PREFIX/previous"

cat > /usr/local/sbin/mail-console <<'WRAPPER'
#!/bin/sh
# Run mail-console as the service user with read access to the mail logs.
set -e
APP=/opt/mail-console/current
EXTRA=""
for g in adm postdrop systemd-journal; do getent group "$g" >/dev/null && EXTRA="$EXTRA -G $g"; done
if [ "$(id -u)" -ne 0 ]; then echo "run with sudo" >&2; exit 1; fi
# shellcheck disable=SC2086
exec runuser -u mailconsole -g mailconsole $EXTRA -- env PYTHONPATH="$APP" PYTHONDONTWRITEBYTECODE=1 \
  MC_ENV_FILE=/etc/mail-console/mail-console.env "$APP/venv/bin/python" -m mailconsole "$@"
WRAPPER
chmod 0755 /usr/local/sbin/mail-console

# --- systemd units -----------------------------------------------------------
for unit in "${UNITS[@]}"; do
  install -m 0644 "$DEST/deploy/systemd/$unit" "$UNIT_DIR/$unit"
done
GROUPS_LINE=""
for g in adm postdrop systemd-journal; do getent group "$g" >/dev/null && GROUPS_LINE="$GROUPS_LINE $g"; done
install -d -m 0755 "$UNIT_DIR/mail-console-collector.service.d"
cat > "$UNIT_DIR/mail-console-collector.service.d/10-groups.conf" <<EOF
# Generated by install.sh: read-only access groups present on this host.
# adm: read /var/log/syslog; postdrop: query the queue with postqueue -j;
# systemd-journal: read the journal when MC_LOG_SOURCE=journald.
[Service]
SupplementaryGroups=${GROUPS_LINE# }
EOF
systemctl daemon-reload
systemctl enable "${UNITS[@]}" >/dev/null

if [ "$START" -eq 0 ] && [ "${#STOPPED[@]}" -gt 0 ]; then
  log "--no-start: ${STOPPED[*]} left stopped; start them with: systemctl start ${STOPPED[*]}"
fi
if [ "$START" -eq 1 ]; then
  log "restarting mail-console services"
  systemctl restart "${UNITS[@]}"
  PORT=$(set -a; . "$ETC_DIR/mail-console.env"; set +a; echo "${MC_PORT:-8710}")
  for _ in $(seq 1 30); do
    if "$DEST/venv/bin/python" -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:$PORT/healthz', timeout=2)" 2>/dev/null; then
      log "web interface healthy on 127.0.0.1:$PORT"
      break
    fi
    sleep 1
  done
  systemctl is-active --quiet mail-console-web || die "mail-console-web failed: journalctl -u mail-console-web"
  systemctl is-active --quiet mail-console-collector || die "mail-console-collector failed: journalctl -u mail-console-collector"
fi

# --- prune old releases ------------------------------------------------------
CURRENT=$(readlink "$PREFIX/current")
KEEP_PREV=$(cat "$PREFIX/previous" 2>/dev/null || true)
ls -1dt "$PREFIX"/releases/*/ | tail -n +$((KEEP_RELEASES + 1)) | while read -r old; do
  old=${old%/}
  [ "releases/$(basename "$old")" = "$CURRENT" ] && continue
  [ "releases/$(basename "$old")" = "$KEEP_PREV" ] && continue
  rm -rf "$old"
done

log "done: release $RELEASE"
if [ -z "$(run_as_service "$DEST" admin list 2>/dev/null)" ]; then
  log "next: create the administrator:  sudo mail-console admin create --username admin"
fi
