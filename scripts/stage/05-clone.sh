#!/usr/bin/env bash
# Split-brain drill: copy the device's keys/ and state/ into simulator-state-clone, then stream BOTH copies.
set -euo pipefail
# shellcheck source=scripts/stage/common.sh
. "$(dirname "$0")/common.sh"
cd "$REPO"
need_device "${1:-}"
DEVICE="$1"
banner "05 clone drill $DEVICE"

# Both copies must start on a leaf that is neither expired nor about to be renewed. If renewal (2/3 of the validity,
# DECISIONS 83) is due within 45 s, both copies renew before their first batch: the second renewal revokes the first
# one's unused pending leaf as REPLACED_BEFORE_USE (the lost-response rule, DECISIONS 85), the loser's first handshake
# is refused, and no sequence number ever collides, so no trap fires (found in the Phase 10a rehearsal). One
# legitimate Protocol C run first gives a fresh leaf with about 100 s before renewal.
CRT="simulator-state/$DEVICE/state/olk.crt"
SECS_TO_DUE="$(python3 - "$CRT" <<'PY'
import subprocess, sys
from datetime import datetime, timezone
def date(flag):
    out = subprocess.run(["openssl", "x509", "-in", sys.argv[1], "-noout", flag], capture_output=True, text=True).stdout
    return datetime.strptime(out.split("=", 1)[1].strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
try:
    nb, na = date("-startdate"), date("-enddate")
    due = nb + (na - nb) * 2 / 3
    print(int((due - datetime.now(timezone.utc)).total_seconds()))
except Exception:
    print(-1)
PY
)"
if [ "$SECS_TO_DUE" -lt 45 ]; then
    echo "leaf renewal due in ${SECS_TO_DUE} s (or already expired): re-enrolling once before cloning"
    "$SIM" re-enroll --device-id "$DEVICE"
fi

rm -rf "$CLONE_DIR"
"$SIM" clone --device-id "$DEVICE" --to-state-dir "$CLONE_DIR"
LOG="$(mktemp "${TMPDIR:-/tmp}/vitalsshield-original.XXXXXX")"
caffeinate -dimsu "$SIM" run --device-id "$DEVICE" --scenario resting --interval-ms 500 >"$LOG" 2>&1 &
ORIG=$!
# A backgrounded job ignores Ctrl-C in a script, so stop the original explicitly when this script ends.
trap 'kill -TERM "$ORIG" 2>/dev/null || true' EXIT
echo "original streaming in the background (pid $ORIG), log: $LOG"
echo ">>> watch the dashboard: $DEVICE goes REAUTH_REQUIRED with a pinned SEQUENCE_REGRESSION alert <<<"
set +e
caffeinate -dimsu "$SIM" run --device-id "$DEVICE" --scenario resting --interval-ms 500 --state-dir "$CLONE_DIR"
CLONE_EXIT=$?
wait "$ORIG"
ORIG_EXIT=$?
set -e
echo "clone exit $CLONE_EXIT; original exit $ORIG_EXIT; original's last lines:"
tail -3 "$LOG"
