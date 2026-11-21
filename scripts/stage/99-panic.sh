#!/usr/bin/env bash
# The live stack is broken on stage: what to say, what to open, how to bring it back.
set -euo pipefail
# shellcheck source=scripts/stage/common.sh
. "$(dirname "$0")/common.sh"
cd "$REPO"
banner "99 panic"

cat <<TEXT
1. Keep talking: open docs/demo-fallback.md (real screenshots and outputs of every beat), or
   git stash && git checkout dashboard-green-v1   (the last known-good dashboard build)
2. Bring the stack back (about 2 minutes):
     docker compose up -d                    # only if a container is down; never stop or restart LocalStack
     $BOOT_CMD
     scripts/stage/00-prestage.sh
3. If the database is in a bad state:   scripts/stage/01-reset.sh   (drops the Compose Postgres volume)
   then register the passkey again with var/admin/setup-code and re-provision dev_stage_001.
4. Afterwards: git checkout main && git stash pop
TEXT
