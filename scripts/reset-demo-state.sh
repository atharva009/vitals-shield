#!/usr/bin/env bash
# Reset the demo to a clean slate (DECISIONS #75). security_audit_log is append-only at the database level, so rows
# are never deleted: the whole Compose Postgres volume is dropped and recreated instead.
#
# Resets: the Compose Postgres volume, simulator-state/, var/admin/, var/devseed/.
# Keeps:  LocalStack (its old KMS keys are simply no longer referenced; the next boot finds no ACTIVE kms_keys rows
#         and rebuilds the CA hierarchy, DECISIONS #12, #14), the host-native Postgres on 5432 (never touched), .env.
set -euo pipefail

cd "$(dirname "$0")/.."

ADMIN_PORT=8445

fail() {
    echo "RESET REFUSED: $1" >&2
    exit 1
}

# 1. The server must be stopped: it holds connections and would recreate var/admin/ mid-reset.
if lsof -nP -iTCP:"$ADMIN_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    fail "something is listening on $ADMIN_PORT (bootRun?). Stop the server first (Ctrl-C in its terminal), then rerun."
fi

# 4 (resolved first, so nothing is stopped if the name cannot be found). The named volume of the postgres service.
VOLUME_KEY="$(docker compose config --format json | python3 -c '
import json, sys
c = json.load(sys.stdin)
for v in c["services"]["postgres"].get("volumes", []):
    if v.get("type") == "volume" and v.get("target") == "/var/lib/postgresql/data":
        print(v["source"])
')"
[ -n "$VOLUME_KEY" ] || fail "cannot find the postgres data volume in docker compose config"
VOLUME="$(docker compose config --format json | python3 -c '
import json, sys
c = json.load(sys.stdin)
print(c["volumes"][sys.argv[1]]["name"])
' "$VOLUME_KEY")"
[ -n "$VOLUME" ] || fail "cannot resolve the name of volume $VOLUME_KEY"
echo "Compose Postgres volume: $VOLUME"

# 2, 3. Stop and remove only the Compose postgres container.
docker compose stop postgres
docker compose rm -f postgres

# 4. Drop the volume.
if docker volume inspect "$VOLUME" >/dev/null 2>&1; then
    docker volume rm "$VOLUME"
else
    echo "volume $VOLUME did not exist"
fi

# 5. Recreate and wait for healthy.
docker compose up -d postgres
echo -n "waiting for postgres to become healthy"
for _ in $(seq 1 60); do
    CID="$(docker compose ps -q postgres)"
    STATUS="$(docker inspect -f '{{.State.Health.Status}}' "$CID" 2>/dev/null || echo starting)"
    if [ "$STATUS" = "healthy" ]; then
        echo " ok"
        break
    fi
    echo -n "."
    sleep 1
done
[ "$STATUS" = "healthy" ] || fail "postgres did not become healthy within 60 s (docker compose logs postgres)"

# 6. Local state that refers to the old database.
rm -rf simulator-state var/admin var/devseed

# 7. LocalStack is intentionally left alone.

# 8. Summary.
cat <<EOF

Reset complete:
  - Compose Postgres volume $VOLUME dropped and recreated (empty; Flyway migrates it on the next boot)
  - simulator-state/, var/admin/, var/devseed/ deleted
  - LocalStack untouched: the next boot finds no ACTIVE kms_keys rows and rebuilds the CA hierarchy (REBUILT)

Next steps:
  1. ./gradlew :server:bootRun --args='--spring.profiles.active=local'
     (expect "Hierarchy reconciliation: REBUILT" and a new var/admin/setup-code)
  2. curl -s http://localhost:8445/api/v1/admin/auth/status   -> passkeys_registered 0 (first-run screen)
  3. Register the first passkey at http://localhost:8445, or seed a demo device:
     ./gradlew -q :server:seedDemoDevice --args="--device-id dev_clinical_001"
EOF
