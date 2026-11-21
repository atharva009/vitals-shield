#!/usr/bin/env bash
# Switches the running stream to the drift scenario (it reads the scenario file before every batch).
set -euo pipefail
# shellcheck source=scripts/stage/common.sh
. "$(dirname "$0")/common.sh"
cd "$REPO"
need_device "${1:-}"
banner "04 drift $1"

"$SIM" scenario --device-id "$1" --set drift
echo "a drift alert needs a LOCKED baseline (10 resting batches) and 4 breaching resting batches"
