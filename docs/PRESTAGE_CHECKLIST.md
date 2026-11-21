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
- [ ] Phase 6 (webauthn mode, the default): open the dashboard at `http://localhost:8445` (not 127.0.0.1; the passkey
      RP id is "localhost"). Register the presenter's passkey with the setup code before the slot and sign in once
      with Touch ID; after that the setup code no longer works for anything (DECISIONS #60). Sessions are in memory:
      a server restart means signing in again. `scripts/demo-cli.sh` now waits for the dashboard quarantine (Touch
      ID); its curl mode works only with `--vitalsshield.admin.auth=bearer`, the cut path.
- [ ] Phase 8.1: run the server and the simulator under `caffeinate -dimsu` (or keep the lid open and on power). With
      the demo PT4M leaves, any sleep longer than about 2 minutes expires the device's certificate and ends the stream
      (exit 4).
- [ ] Do not leave a PT4M device streaming unattended; use the default 12 h profile for long runs.
- [ ] Phase 9 (DECISIONS 98): after any laptop sleep, check the dashboard's clock skew tile, and restart Docker Desktop
      if it is amber (above 2 s) or red (above 10 s).
- [ ] Phase 10a (DECISIONS 99): start the server for every rehearsal and the live run with
      `caffeinate -dimsu ./gradlew :server:bootRun --args='--spring.profiles.active=demo'`, then run
      `scripts/stage/00-prestage.sh` and continue only when every line is PASS. The ordered T-60/T-15/T-2 lists are in
      `docs/DEMO_RUNBOOK.md`; if the stack dies on stage, run `scripts/stage/99-panic.sh` and open
      `docs/demo-fallback.md`.
- [ ] Phase 10a.1 (DECISIONS 99): demo leaves are now PT3M. A leaf expires about 120 s after issuance, so with the demo
      profile any sleep longer than about 1 minute expires a streaming device's certificate. Protocol C recovers it on
      the next batch, but on stage keep the lid open, power in, and everything under `caffeinate -dimsu`.
