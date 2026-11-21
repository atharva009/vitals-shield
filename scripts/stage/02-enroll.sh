#!/usr/bin/env bash
# Protocol A with the bootstrap token shown on the dashboard after the Touch ID provisioning.
set -euo pipefail
# shellcheck source=scripts/stage/common.sh
. "$(dirname "$0")/common.sh"
cd "$REPO"
need_device "${1:-}"
DEVICE="$1"
TOKEN="${2:-}"
[ -n "$TOKEN" ] || { echo "usage: $0 DEVICE_ID TOKEN" >&2; exit 2; }
banner "02 enroll $DEVICE"

"$SIM" factory-wipe --device-id "$DEVICE"
"$SIM" enroll --device-id "$DEVICE" --token "$TOKEN"
