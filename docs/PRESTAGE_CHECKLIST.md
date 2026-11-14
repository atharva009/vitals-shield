# Pre-stage checklist

Run through this before the demo slot. Later phases append to it.

- [ ] Start the Compose stack while online (LocalStack validates its token at startup).
- [ ] Never run `scripts/kms-probe.sh --restart`, `docker compose stop`, `docker compose down`, or
      `docker compose restart` after the final boot before the slot: each wipes KMS keys and forces a rebuild that
      revokes every device.
- [ ] Run `./gradlew clean build` before the final boot.
- [ ] Restart the server within 24 h of the slot (gateway TLS cert lifetime).
- [ ] Confirm `GET /api/v1/admin/boot-status` lists all eight steps (RECONCILED, SERIALS_SWEPT, GATEWAY_TLS_ISSUED,
      TRUST_ANCHORS_LOADED, DENY_LIST_SEEDED, CRLS_PUBLISHED, ADMIN_CODE_ISSUED, LISTENERS_BOUND).
- [ ] Read the admin bearer from `var/admin/setup-code` (mode 600, regenerated every boot); never paste it into slides.
- [ ] Do not run `./gradlew drillTest` after the final boot: it restarts LocalStack and wipes the KMS keys.
- [ ] Build the simulator binary with `./gradlew :simulator:installDist` and drive the demo with
      `simulator/build/install/simulator/bin/simulator` (or `scripts/demo-cli.sh`), run from the repo root. Never use
      `./gradlew :simulator:run` on stage: the simulator's designed exit code 3 after quarantine makes Gradle print
      `BUILD FAILED`.
- [ ] Build the dashboard (`cd dashboard && npm ci && npm run build`) and open `http://127.0.0.1:8445/` once to
      confirm it loads and signs in.
