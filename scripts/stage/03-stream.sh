#!/usr/bin/env bash
# Streams one resting batch per second. Ctrl-C stops it cleanly (the next run continues the sequence numbers).
set -euo pipefail
# shellcheck source=scripts/stage/common.sh
. "$(dirname "$0")/common.sh"
cd "$REPO"
need_device "${1:-}"
DEVICE="$1"
banner "03 stream $DEVICE (Ctrl-C to stop)"

caffeinate -dimsu "$SIM" run --device-id "$DEVICE" --scenario resting &
PID=$!
trap 'kill -TERM "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; echo; echo "stream stopped"; exit 0' INT TERM
set +e
wait "$PID"
CODE=$?
set -e
echo "simulator exit $CODE (0 done, 3 refused/revoked, 4 expired and unrecoverable, 5 REAUTH_REQUIRED)"
exit "$CODE"
