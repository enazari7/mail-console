#!/usr/bin/env bash
# Update an existing installation to the code in this checkout.
#   git -C /path/to/mail-console pull && sudo /path/to/mail-console/deploy/update.sh
# Takes a database backup, applies migrations, switches the release atomically
# and restarts only the two mail-console services. See docs/DEPLOYMENT.md.
set -euo pipefail
[ -L /opt/mail-console/current ] || { echo "mail-console is not installed; use install.sh" >&2; exit 1; }
exec "$(dirname "${BASH_SOURCE[0]}")/install.sh" "$@"
