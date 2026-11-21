#!/usr/bin/env bash
# Clean slate: drops the Compose Postgres volume (never DELETE/UPDATE on security_audit_log, DECISIONS 75), then waits
# for you to start the server with the demo profile in another terminal.
set -euo pipefail
# shellcheck source=scripts/stage/common.sh
. "$(dirname "$0")/common.sh"
cd "$REPO"
banner "01 reset"

scripts/reset-demo-state.sh
rm -rf "$CLONE_DIR"
echo
echo "start bootRun with: $BOOT_CMD"
echo -n "waiting for the server on 8445"
for _ in $(seq 1 600); do
    if curl -fsS --max-time 2 "$ADMIN_URL/api/v1/admin/boot-status" 2>/dev/null | grep -q LISTENERS_BOUND; then
        echo " up"
        echo "setup code for the first passkey: var/admin/setup-code (do not show it on screen)"
        exit 0
    fi
    echo -n "."
    sleep 1
done
echo " not up after 10 minutes" >&2
exit 1
