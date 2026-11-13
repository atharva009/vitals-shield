#!/usr/bin/env bash
# Phase 0 KMS gate: create an ECC_NIST_P256 key and sign with it.
# With --restart, also restart LocalStack and check whether the key survives.
# WARNING: --restart wipes every KMS key in LocalStack (persistence is off), so
# the next server boot rebuilds the whole CA hierarchy and revokes all leaves.
# Runs awslocal inside the LocalStack container; no host AWS CLI is needed.
#
# Usage: scripts/kms-probe.sh [--restart]
set -uo pipefail
cd "$(dirname "$0")/.."

RESTART=false
for arg in "$@"; do
  case "$arg" in
    --restart) RESTART=true ;;
    *) echo "usage: $0 [--restart]" >&2; exit 2 ;;
  esac
done

CREATE=fail
SIGN=fail
SURVIVES_RESTART=skipped

# awslocal prints a deprecation banner on stderr; keep stderr in a log and
# show it only if a step fails, so stdout stays a single result line.
ERR_LOG="$(mktemp)"
trap 'rm -f "$ERR_LOG"' EXIT

aws_ls() {
  docker compose exec -T localstack awslocal --region us-east-1 "$@" 2>>"$ERR_LOG"
}

wait_healthy() {
  local cid
  cid="$(docker compose ps -q localstack)"
  for _ in $(seq 1 60); do
    if [ "$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null)" = "healthy" ]; then
      return 0
    fi
    sleep 2
  done
  return 1
}

KEY_ID="$(aws_ls kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY \
  --query KeyMetadata.KeyId --output text)" || KEY_ID=""
if [ -n "$KEY_ID" ] && [ "$KEY_ID" != "None" ]; then
  CREATE=ok
  MSG_B64="$(printf 'vitalsshield-kms-probe' | base64)"
  SIG="$(aws_ls kms sign --key-id "$KEY_ID" --message "$MSG_B64" --message-type RAW \
    --signing-algorithm ECDSA_SHA_256 --query Signature --output text)" || SIG=""
  if [ -n "$SIG" ] && [ "$SIG" != "None" ]; then
    SIGN=ok
  fi

  if [ "$RESTART" = true ]; then
    SURVIVES_RESTART=no
    docker compose restart localstack >/dev/null 2>&1
    if wait_healthy; then
      if aws_ls kms describe-key --key-id "$KEY_ID" >/dev/null 2>&1; then
        SURVIVES_RESTART=yes
      fi
    else
      echo "localstack did not become healthy after restart" >&2
    fi
  fi
fi

if [ "$CREATE" = fail ] || [ "$SIGN" = fail ]; then
  grep -v -e "awslocal" -e "lstk" -e "^=*$" -e "^ *$" -e "Continuing with" "$ERR_LOG" >&2
fi

echo "CREATE=$CREATE SIGN=$SIGN SURVIVES_RESTART=$SURVIVES_RESTART"
