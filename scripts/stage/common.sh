#!/usr/bin/env bash
# Shared by scripts/stage/*.sh. Sourced, not run.
# shellcheck disable=SC2034
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SIM="$REPO/simulator/build/install/simulator/bin/simulator"
ADMIN_URL="http://127.0.0.1:8445"
CLONE_DIR="simulator-state-clone"
BOOT_CMD="caffeinate -dimsu ./gradlew :server:bootRun --args='--spring.profiles.active=demo'"

banner() {
    echo "== VitalsShield stage: $* =="
}

need_device() {
    if [ -z "${1:-}" ]; then
        echo "usage: $0 DEVICE_ID" >&2
        exit 2
    fi
}
