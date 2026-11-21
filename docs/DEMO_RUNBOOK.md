# Demo runbook (Phase 10a)

The live run uses the demo profile (DECISIONS 99) on this laptop, plugged in, lid open. Every command is run from
the repo root. The stage scripts are in `scripts/stage/`. If anything dies on stage, run `scripts/stage/99-panic.sh`
and switch to `docs/demo-fallback.md`.

Device IDs:

- `dev_precheck_001`: the T-15 precheck only.
- `dev_stage_001`: the live run (beats 3 to 7).
- `dev_stage_002`: the clone drill (beat 8). It is a second device because the quarantine in beat 7 clears
  dev_stage_001's device key (DEK), and without the DEK a device can never re-enroll.

Terminals: **A** server, **B** stream, **C** commands. Browser: `http://localhost:8445` (not 127.0.0.1: the passkey
RP id is "localhost").

## T-60 min

1. Power adapter in. Lid stays open until the end. Close every app that might sleep the machine.
2. Docker Desktop running. `docker compose up -d` while online (LocalStack validates its token at startup). From here
   on, never `docker compose stop`, `down` or `restart`, never `scripts/kms-probe.sh --restart`, never `./gradlew
   drillTest`: each one wipes the KMS keys.
3. `./gradlew clean build` (all tests, about 10 minutes) and `./gradlew :simulator:installDist`.
4. `cd dashboard && npm ci && npm run build && cd ..`
5. Terminal C: `scripts/stage/01-reset.sh`. It drops the Compose database, then waits for the server.
6. Terminal A: `caffeinate -dimsu ./gradlew :server:bootRun --args='--spring.profiles.active=demo'`. Expect
   `Hierarchy reconciliation: REBUILT`, then 01-reset.sh prints `up`.
7. Browser: `http://localhost:8445`. Register the presenter's passkey (Touch ID) with the code in
   `var/admin/setup-code`. Never show that file on screen. After this, the setup code no longer works (DECISIONS 60).

## T-15 min

1. Terminal C: `scripts/stage/00-prestage.sh`. Every line must be PASS. FAIL on caffeinate means terminal A was not
   started under `caffeinate`. FAIL on clock skew means restarting Docker Desktop, then going back to T-60 step 5.
2. Precheck device: on the dashboard, Provision `dev_precheck_001` (Touch ID). Then
   `scripts/stage/02-enroll.sh dev_precheck_001 <token>`, then
   `simulator/build/install/simulator/bin/simulator run --device-id dev_precheck_001 --count 5`. All 5 must be
   `status=200`.
3. Clone-drill device: Provision `dev_stage_002` (Touch ID), then `scripts/stage/02-enroll.sh dev_stage_002 <token>`.
   Do not stream it. 05-clone.sh renews its identity first if the leaf has expired by then.
4. Dashboard: sign out and sign in again with Touch ID. Set the zoom so the tiles row and the Devices table fit.
   Leave "High contrast" off unless the projector is washed out.

## T-2 min

1. Terminal A shows the server log; terminals B and C are at the repo root with their commands typed but not run:
   B: `scripts/stage/03-stream.sh dev_stage_001`. C: empty.
2. Dashboard scrolled to the top, signed in, the "stale" pill not showing, the clock skew tile GREEN.
3. Notifications off (Do Not Disturb). Touch ID finger ready.

## The 5-minute script

Planned times are from the brief; "rehearsal" is when the beat actually started in the timed rehearsal (headless
Chrome with a virtual authenticator, demo profile, 2026-11-20). A beat that ran long is marked.

| # | Planned | Rehearsal | What I say | What I do | What the audience should see | If it does not appear |
|---|---|---|---|---|---|---|
| 1 | 0:00 | 0:00 (4 s) | "A wearable sends a patient's vitals. Anyone who copies its keys can forge them, and a clinician acts on them." | Dashboard at the top. Point at the tiles. | Boot complete, KMS HEALTHY, clock skew GREEN, 0 sockets | Pills not green: `scripts/stage/00-prestage.sh` in C; if it FAILs, `99-panic.sh` |
| 2 | 0:15 | 0:04 (9 s) | "Every certificate here is signed by a key that never leaves AWS KMS. The server cannot copy it." | Scroll to Trust chain. | Root CA, Device Intermediate, Server TLS CA, each with its SKI; the CRL link | Empty chain: the server is still booting; wait for "Boot complete" |
| 3 | 0:35 | 0:13 (2 s) | "A clinician approves the device with Touch ID. That approval is what makes the device trusted." | Provision `dev_stage_001`, patient `patient-stage-001`, Touch ID. Copy the token. C: `scripts/stage/02-enroll.sh dev_stage_001 <token>` | Token box "Shown once"; C prints `ENROLLED serial=… boot_epoch=1` | `ENROLL_FAILED`: re-provision (the token is single-use) and enroll again |
| 4 | 1:15 | 0:15 (16 s) | "It streams one signed batch a second. Each one is checked against the certificate on that very connection." | B: `scripts/stage/03-stream.sh dev_stage_001`. Click the device row. | Sockets 1, Last seq rising, baseline CALIBRATING then LOCKED after 10 batches | No rows: look at B; exit 4 or 5 means the enroll in beat 3 did not finish |
| 5 | 1:45 | 0:31 (85 s, **ran long**) | "Its certificate lives 4 minutes here. It renews itself at two thirds, with no human, and the old one stops working 60 seconds later." | Point at "Next renewal due" on the card, then the Renewal log. | B prints `RENEWED` then `ACTIVATED`; Renewal log row; old serial with a grace countdown | It comes 1m40s after the enroll in beat 3, not at a fixed time: keep talking over beat 4, or do beat 6 first and come back |
| 6 | 2:05 | 1:56 (5 s) | "Now the readings drift from this patient's own baseline." | C: `scripts/stage/04-drift.sh dev_stage_001` | Within about 5 batches: DRIFT alert "Drift vs baseline v1: HR z=+5.x, HRV z=-3.x, SpO2 z=-2.x over 4 resting batches" | No alert: baseline not LOCKED yet (needs 10 resting batches); wait |
| 7 | 2:45 | 2:01 (3 s) | "Suppose this device was stolen. One Touch ID revokes it, closes its connection, and retracts what it reported." | Device panel: Quarantine, reason, "Approve quarantine with passkey", Touch ID. | Result "revocation latency … ms … approved by"; B: `REJECTED handshake_refused` and exit 3; the alert struck through; baseline CALIBRATING v2 | Dialog does not close: Touch ID cancelled; press Approve again |
| 8 | 3:45 | 2:04 (14 s) | "Now someone copies a device's flash and runs both. Neither knows the other exists. The server sees them collide." | C: `scripts/stage/05-clone.sh dev_stage_002`. Click dev_stage_002. Then "Restore (benign reset)", Touch ID. C: `scripts/stage/06-recover.sh dev_stage_002` | Both copies exit 3; REAUTH_REQUIRED panel with SEQUENCE_REGRESSION and two buttons; pinned SECURITY alert; after Restore, `RE-ENROLLED … boot_epoch=2` and 10 batches at 200 | No panel within 5 s: read 05-clone.sh output; if it says "re-enrolling once", wait for it; never run it twice in parallel |
| 9 | 4:30 | 2:18 (11 s) | "What is real today: KMS-signed certificates, mTLS on every request, live revocation, the three clone traps. What is designed only: a second CA for failover, multi-gateway eviction with Redis, a secure element for the device key. A clone that re-enrolls while the real device is off goes unnoticed until it comes back." | Scroll to the Audit log. | chain valid, 10 entries: passkey, provisioning, DEVICE_QUARANTINED, SECURITY_ANOMALY by system, DEVICE_RESTORED | Nothing to fix: this beat is talk |

## Rehearsal record

Rehearsed on 2026-11-20 at 19:15 to 19:18 EST (2026-11-21 00:15 to 00:18 UTC) by `scripts/rehearsal/rehearse.mjs`: headless Chrome 1440x900, a CDP
virtual authenticator for every Touch ID step, the stage scripts above, the demo profile, after
`scripts/stage/01-reset.sh`. It was the fourth run. Runs 1 to 3 found the clone-drill bug, the screenshot problems and
the alerts-table overflow listed in the Phase 10a report.

- T-15 steps (passkey, `dev_precheck_001` with 5 batches at 200, `dev_stage_002` enrolled) and
  `00-prestage.sh` (all PASS) ran before the clock started.
- The automated run took **2:30** for all nine beats, because it does not talk. Spoken, the beats fit the 5-minute plan
  except one.
- **Beat 5 (rollover) ran long: 85 s** of waiting. The renewal is due 1m40s after the leaf is issued (DECISIONS 83),
  so it lands 1m40s after beat 3's enroll, not at 1:45 on the clock. Spoken, with the enroll at about 0:45, the
  rollover arrives at about 2:25. Plan to cover it in beat 4, or run beat 6 first and come back to the Renewal log.
- Beat 8 needed one Protocol C refresh before cloning. `dev_stage_002`'s leaf, enrolled at T-15, was past its renewal
  time ("leaf renewal due in -26 s"), so 05-clone.sh re-enrolled it once. The trap then fired after the clone's third
  batch, about 1 s after both copies started.
- Console messages: none. Page exceptions: none. Horizontal overflow at 1440 px: none.

| Beat | Started | Took | Result line |
|---|---|---|---|
| 1 problem | 0:00 | 4 s | dashboard landing, signed in |
| 2 trust chain | 0:04 | 9 s | CRL #1, 0 entries; 4 ACTIVE KMS keys |
| 3 provisioning + enroll | 0:13 | 2 s | `ENROLLED serial=2f7b5063affc16dde4a2de0c8b1c9e96b3763a2b boot_epoch=1 not_after=2026-11-21T00:19:12Z` |
| 4 streaming | 0:15 | 16 s | baseline LOCKED after 16 batches |
| 5 rollover | 0:31 | **85 s** | `RENEWED old=2F7B5063… new=19150614… at=00:17:52.333Z`, `ACTIVATED … at=00:17:52.357Z` |
| 6 drift | 1:56 | 5 s | DRIFT alert "HR z=+5.3, HRV z=-3.8, SpO2 z=-2.4 over 4 resting batches" |
| 7 quarantine | 2:01 | 3 s | 2 certs revoked, 1 socket closed, 12.6 ms, 104 batches quarantined; simulator exit 3 |
| 8 clone + restore | 2:04 | 14 s | SEQUENCE_REGRESSION, both copies exit 3; restored; `RE-ENROLLED serial=775AB2F6… boot_epoch=2` |
| 9 close | 2:18 | 11 s | audit chain valid, 10 entries |
