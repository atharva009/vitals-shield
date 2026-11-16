#!/usr/bin/env bash
# CLI demo: seed, enroll, stream, quarantine, verify. Run from anywhere; it works in the repo root.
# Assumes `docker compose up -d` and `./gradlew :server:bootRun --args='--spring.profiles.active=local'` in another
# terminal.
#
#   DEMO_PAUSE=2          seconds between steps
#   DEMO_QUARANTINE=ui    (default) wait for the operator to press Quarantine on the dashboard (Touch ID step-up)
#   DEMO_QUARANTINE=curl  single-step curl quarantine with the setup code; bearer mode only
#                         (vitalsshield.admin.auth=bearer, DECISIONS #60)
#   DEMO_DEVICE=dev_wearable_019
set -euo pipefail

cd "$(dirname "$0")/.."

PAUSE="${DEMO_PAUSE:-2}"
MODE="${DEMO_QUARANTINE:-ui}"
DEVICE="${DEMO_DEVICE:-dev_wearable_019}"
SIM=simulator/build/install/simulator/bin/simulator
ADMIN=http://127.0.0.1:8445
PUBLIC=https://127.0.0.1:8444
CODE_FILE=var/admin/setup-code
TRUST=var/trust/root-ca.pem
LOG="$(mktemp "${TMPDIR:-/tmp}/vitalsshield-sim.XXXXXX")"
SIM_PID=""

step_no=0
step() {
    step_no=$((step_no + 1))
    [ "$step_no" -gt 1 ] && sleep "$PAUSE"
    echo
    echo "=================================================================="
    echo " Step $step_no: $1"
    echo "=================================================================="
}

fail() {
    echo
    echo "DEMO FAILED: $1" >&2
    exit 1
}

cleanup() {
    if [ -n "$SIM_PID" ] && kill -0 "$SIM_PID" 2>/dev/null; then
        kill "$SIM_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# OpenSSL form of a stored serial: uppercase, whole bytes (DECISIONS #50).
openssl_serial() {
    local hex
    hex="$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"
    if [ $(( ${#hex} % 2 )) -eq 1 ]; then hex="0$hex"; fi
    printf '%s' "$hex"
}

# ---------------------------------------------------------------------------------------------------------------
step "Preflight"
curl -sf -o /dev/null "$ADMIN/api/v1/admin/boot-status" || fail "server not reachable on $ADMIN (start bootRun first)"
[ -r "$CODE_FILE" ] || fail "$CODE_FILE not readable (has the server finished booting?)"
[ -r "$TRUST" ] || fail "$TRUST missing"
AUTH_MODE="$(curl -sf "$ADMIN/api/v1/admin/auth/status" | sed -n 's/.*"mode":"\([a-z]*\)".*/\1/p')"
[ -n "$AUTH_MODE" ] || fail "cannot read $ADMIN/api/v1/admin/auth/status"
echo "server up on 8445 (admin auth mode: $AUTH_MODE); trust anchor $TRUST"
if [ "$MODE" = "curl" ] && [ "$AUTH_MODE" != "bearer" ]; then
    fail "DEMO_QUARANTINE=curl needs the server in bearer mode (--vitalsshield.admin.auth=bearer). In webauthn mode quarantine requires a passkey step-up: run with DEMO_QUARANTINE=ui and use the dashboard at http://localhost:8445"
fi
if [ ! -x "$SIM" ]; then
    echo "building simulator binary (installDist)"
    ./gradlew -q :simulator:installDist
fi
echo "simulator binary: $SIM"

# ---------------------------------------------------------------------------------------------------------------
step "Seed $DEVICE (dev seed tool, $AUTH_MODE mode: device, assignment, bootstrap token)"
# webauthn mode: the dev-seed software passkey (var/devseed/passkey.key) approves the ProvisioningDigest, so the token
# passes the same Protocol A re-verification as a Touch ID approval (DECISIONS #57).
SEED_OUT="$(./gradlew -q :server:seedDemoDevice --args="--device-id $DEVICE --auth $AUTH_MODE")"
TOKEN="$(printf '%s\n' "$SEED_OUT" | sed -n 's/^BOOTSTRAP_TOKEN=//p' | head -1)"
[ -n "$TOKEN" ] || fail "seedDemoDevice printed no BOOTSTRAP_TOKEN"
echo "bootstrap token issued (${#TOKEN} chars, single use)"

# ---------------------------------------------------------------------------------------------------------------
step "Factory-wipe the simulated device, then enroll (Protocol A)"
"$SIM" factory-wipe --device-id "$DEVICE"
ENROLL_OUT="$("$SIM" enroll --device-id "$DEVICE" --token "$TOKEN")" || fail "enroll failed: $ENROLL_OUT"
echo "$ENROLL_OUT"
SERIAL="$(printf '%s' "$ENROLL_OUT" | sed -n 's/.*serial=\([0-9a-f]*\).*/\1/p')"
EPOCH="$(printf '%s' "$ENROLL_OUT" | sed -n 's/.*boot_epoch=\([0-9]*\).*/\1/p')"
[ -n "$SERIAL" ] && [ -n "$EPOCH" ] || fail "could not parse the ENROLLED line"
SERIAL_OSSL="$(openssl_serial "$SERIAL")"
echo "serial (OpenSSL form): $SERIAL_OSSL"

# ---------------------------------------------------------------------------------------------------------------
step "Stream signed telemetry over mTLS (one JWS batch per second)"
"$SIM" run --device-id "$DEVICE" > "$LOG" 2>&1 &
SIM_PID=$!
echo "simulator pid $SIM_PID, log $LOG"
for _ in $(seq 1 30); do
    [ "$(grep -c '^SENT' "$LOG" || true)" -ge 10 ] && break
    kill -0 "$SIM_PID" 2>/dev/null || break
    sleep 1
done
grep '^SENT' "$LOG" | head -10
[ "$(grep -c '^SENT.*status=200' "$LOG" || true)" -ge 1 ] || fail "no batch was accepted"

# ---------------------------------------------------------------------------------------------------------------
if [ "$MODE" = "ui" ]; then
    step "Quarantine from the dashboard"
    echo "Quarantine the device from the dashboard now (http://localhost:8445): select $DEVICE, Quarantine, Touch ID"
    echo "waiting for the simulator to be cut off..."
else
    step "Quarantine $DEVICE (admin API, bearer from $CODE_FILE)"
    RESP="$(curl -s -X POST \
        -H "Authorization: Bearer $(cat "$CODE_FILE")" \
        -H "Content-Type: application/json" \
        -d '{"lookback_minutes":10,"reason":"cli demo"}' \
        "$ADMIN/api/v1/admin/devices/$DEVICE/quarantine")"
    if command -v jq >/dev/null 2>&1; then printf '%s\n' "$RESP" | jq .; else printf '%s\n' "$RESP"; fi
fi

set +e
wait "$SIM_PID"
SIM_EXIT=$?
set -e
SIM_PID=""

# ---------------------------------------------------------------------------------------------------------------
step "Simulator after quarantine (exit code $SIM_EXIT)"
tail -3 "$LOG"

# ---------------------------------------------------------------------------------------------------------------
step "Database: device state and telemetry trust_state counts (boot epoch $EPOCH)"
psql_q() {
    docker compose exec -T postgres psql -U vitalsshield -d vitalsshield -v ON_ERROR_STOP=1 "$@"
}
psql_q -c "SELECT device_id, trust_state, boot_epoch, dek_spki_der_b64 IS NULL AS dek_cleared FROM devices WHERE device_id = '$DEVICE';"
psql_q -c "SELECT trust_state, count(*) FROM telemetry_records WHERE device_id = '$DEVICE' AND boot_epoch = $EPOCH GROUP BY trust_state ORDER BY trust_state;"
COUNTS="$(psql_q -At -F '=' -c "SELECT trust_state, count(*) FROM telemetry_records WHERE device_id = '$DEVICE' AND boot_epoch = $EPOCH GROUP BY trust_state;")"
DEVICE_STATE="$(psql_q -At -c "SELECT trust_state FROM devices WHERE device_id = '$DEVICE';")"

# ---------------------------------------------------------------------------------------------------------------
step "Intermediate CRL over 8444: serial $SERIAL_OSSL"
CRL_TEXT="$(curl -sf --cacert "$TRUST" "$PUBLIC/api/v1/pki/intermediate-crl.pem" | openssl crl -noout -text)"
echo "CRL number: $(printf '%s\n' "$CRL_TEXT" | grep -A1 'CRL Number' | tail -1 | tr -d ' ')"
printf '%s\n' "$CRL_TEXT" | grep -m1 'Next Update' | sed 's/^ *//'
CRL_HIT="$(printf '%s\n' "$CRL_TEXT" | grep -A4 "Serial Number: $SERIAL_OSSL" || true)"
if [ -n "$CRL_HIT" ]; then printf '%s\n' "$CRL_HIT"; else echo "serial $SERIAL_OSSL not on the CRL"; fi

# ---------------------------------------------------------------------------------------------------------------
step "Result"
OK=1
[ "$SIM_EXIT" -eq 3 ] || { echo "expected simulator exit 3 (refused), got $SIM_EXIT"; OK=0; }
grep -q 'REJECTED handshake_refused' "$LOG" || { echo "simulator did not report handshake_refused"; OK=0; }
printf '%s\n' "$COUNTS" | grep -q '^QUARANTINED=[1-9]' || { echo "no QUARANTINED telemetry for epoch $EPOCH"; OK=0; }
printf '%s\n' "$COUNTS" | grep -qE '^(ACCEPTED|SIGNAL_DEGRADED)=' && { echo "trusted telemetry left in epoch $EPOCH"; OK=0; }
[ "$DEVICE_STATE" = "QUARANTINED" ] || { echo "device state is $DEVICE_STATE, expected QUARANTINED"; OK=0; }
[ -n "$CRL_HIT" ] || { echo "serial not on the intermediate CRL"; OK=0; }
if [ "$OK" -eq 1 ]; then
    echo "DEMO OK: simulator refused (exit 3), telemetry quarantined, device QUARANTINED, serial on the CRL"
    exit 0
fi
fail "see the messages above"
