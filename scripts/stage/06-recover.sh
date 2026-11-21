#!/usr/bin/env bash
# After "Restore (benign reset)" on the dashboard: the original re-enrolls (epoch resync) and streams 10 batches.
set -euo pipefail
# shellcheck source=scripts/stage/common.sh
. "$(dirname "$0")/common.sh"
cd "$REPO"
need_device "${1:-}"
DEVICE="$1"
banner "06 recover $DEVICE"

"$SIM" re-enroll --device-id "$DEVICE"
"$SIM" run --device-id "$DEVICE" --scenario resting --count 10 --interval-ms 500
