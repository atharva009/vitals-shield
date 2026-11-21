#!/usr/bin/env bash
# Pre-stage checks (docs/DEMO_RUNBOOK.md T-15). Prints PASS or FAIL per check; exits non-zero if any FAIL.
set -euo pipefail
# shellcheck source=scripts/stage/common.sh
. "$(dirname "$0")/common.sh"
cd "$REPO"
banner "00 prestage checks"

FAILS=0
check() {
    local name="$1"
    shift
    local detail
    if detail="$("$@" 2>&1)"; then
        printf 'PASS  %-38s %s\n' "$name" "$detail"
    else
        printf 'FAIL  %-38s %s\n' "$name" "$detail"
        FAILS=$((FAILS + 1))
    fi
}

docker_running() { docker info --format '{{.ServerVersion}}' >/dev/null && echo "docker $(docker info --format '{{.ServerVersion}}')"; }
compose_healthy() {
    local svc cid status out=""
    for svc in postgres localstack; do
        cid="$(docker compose ps -q "$svc")"
        [ -n "$cid" ] || { echo "$svc not running"; return 1; }
        status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid")"
        [ "$status" = "healthy" ] || { echo "$svc $status"; return 1; }
        out="$out$svc healthy "
    done
    echo "$out"
}
localstack_pro() {
    local edition
    edition="$(curl -fsS http://localhost:4566/_localstack/info | python3 -c 'import json,sys; print(json.load(sys.stdin).get("edition",""))')"
    [ "$edition" = "pro" ] || { echo "edition=$edition"; return 1; }
    echo "edition=pro"
}
caffeinate_running() { pgrep -x caffeinate >/dev/null && echo "pid $(pgrep -x caffeinate | head -1)"; }
boot_status() { curl -fsS --max-time 3 "$ADMIN_URL/api/v1/admin/boot-status"; }
server_demo() {
    local s
    s="$(boot_status)" || { echo "no answer on 8445"; return 1; }
    echo "$s" | python3 -c '
import json, sys
p = json.load(sys.stdin).get("active_profiles", [])
print("profiles=" + ",".join(p))
sys.exit(0 if "demo" in p else 1)'
}
all_steps() {
    boot_status | python3 -c '
import json, sys
want = ["RECONCILED", "SERIALS_SWEPT", "GATEWAY_TLS_ISSUED", "TRUST_ANCHORS_LOADED", "DENY_LIST_SEEDED",
        "CRLS_PUBLISHED", "ADMIN_CODE_ISSUED", "LISTENERS_BOUND"]
got = [s["step"] for s in json.load(sys.stdin)["steps"]]
missing = [w for w in want if w not in got]
print("missing " + ",".join(missing) if missing else "all 8 steps")
sys.exit(1 if missing else 0)'
}
kms_healthy() {
    boot_status | python3 -c '
import json, sys
s = json.load(sys.stdin).get("kms_state")
print("kms_state=%s" % s)
sys.exit(0 if s == "HEALTHY" else 1)'
}
clock_ok() {
    boot_status | python3 -c '
import json, sys
c = json.load(sys.stdin).get("clock", {})
ms = c.get("skew_ms")
print("skew_ms=%s state=%s" % (ms, c.get("state")))
sys.exit(0 if ms is not None and abs(ms) < 2000 else 1)'
}
sim_present() { [ -x "$SIM" ] && echo "$SIM"; }
dashboard_built() { [ -f dashboard/out/index.html ] && echo "dashboard/out/index.html $(date -r dashboard/out/index.html '+%F %T')"; }
disk_free() {
    local kb
    kb="$(df -Pk "$REPO" | awk 'NR==2 {print $4}')"
    echo "$((kb / 1024 / 1024)) GB free"
    [ "$kb" -gt $((2 * 1024 * 1024)) ]
}

check "Docker running" docker_running
check "Compose postgres and localstack healthy" compose_healthy
check "LocalStack edition pro" localstack_pro
check "caffeinate running" caffeinate_running
check "Server on 8445 with demo profile" server_demo
check "Boot status has all steps" all_steps
check "KMS health HEALTHY" kms_healthy
check "Clock skew under 2 s" clock_ok
check "Simulator binary present" sim_present
check "Dashboard built" dashboard_built
check "Free disk over 2 GB" disk_free

if [ "$FAILS" -gt 0 ]; then
    echo "PRESTAGE: $FAILS check(s) FAILED"
    exit 1
fi
echo "PRESTAGE: all checks PASS"
