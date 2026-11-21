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
Chrome with a virtual authenticator, demo profile with PT3M leaves, Phase 10a.1). A beat that ran long is marked.

| # | Planned | Rehearsal | What I say | What I do | What the audience should see | If it does not appear |
|---|---|---|---|---|---|---|
| 1 | 0:00 | 0:00 (4 s) | "A wearable sends a patient's vitals. Anyone who copies its keys can forge them, and a clinician acts on them." | Dashboard at the top. Point at the tiles. | Boot complete, KMS HEALTHY, clock skew GREEN, 0 sockets | Pills not green: `scripts/stage/00-prestage.sh` in C; if it FAILs, `99-panic.sh` |
| 2 | 0:15 | 0:04 (9 s) | "Every certificate here is signed by a key that never leaves AWS KMS. The server cannot copy it." | Scroll to Trust chain. | Root CA, Device Intermediate, Server TLS CA, each with its SKI; the CRL link | Empty chain: the server is still booting; wait for "Boot complete" |
| 3 | 0:35 | 0:13 (2 s) | "A clinician approves the device with Touch ID. That approval is what makes the device trusted." | Provision `dev_stage_001`, patient `patient-stage-001`, Touch ID. Copy the token. C: `scripts/stage/02-enroll.sh dev_stage_001 <token>` | Token box "Shown once"; C prints `ENROLLED serial=… boot_epoch=1` | `ENROLL_FAILED`: re-provision (the token is single-use) and enroll again |
| 4 | 1:15 | 0:15 (16 s) | "It streams one signed batch a second. Each one is checked against the certificate on that very connection." | B: `scripts/stage/03-stream.sh dev_stage_001`. Click the device row. | Sockets 1, Last seq rising, baseline CALIBRATING then LOCKED after 10 batches | No rows: look at B; exit 4 or 5 means the enroll in beat 3 did not finish |
| 5 | 1:45 | 0:31 (45 s) | "Its certificate lives 3 minutes here. It renews itself at two thirds, with no human, and the old one stops working 60 seconds later." | Point at "Next renewal due" on the card, then the Renewal log. | B prints `RENEWED` then `ACTIVATED`; Renewal log row; old serial with a grace countdown | It comes 60 s after the enroll in beat 3 (PT3M, DECISIONS 99): with the enroll at about 0:45 it lands at about 1:45; if beat 3 ran late, keep talking over beat 4 |
| 6 | 2:05 | 1:16 (5 s) | "Now the readings drift from this patient's own baseline." | C: `scripts/stage/04-drift.sh dev_stage_001` | Within about 5 batches: DRIFT alert "Drift vs baseline v1: HR z=+4.x, HRV z=-3.x, SpO2 z=-2.x over 4 resting batches" | No alert: baseline not LOCKED yet (needs 10 resting batches); wait |
| 7 | 2:45 | 1:21 (6 s) | "Suppose this device was stolen. One Touch ID revokes it, closes its connection, and retracts what it reported." | Device panel: Quarantine, reason, "Approve quarantine with passkey", Touch ID. | Result "revocation latency … ms … approved by"; B: `REJECTED handshake_refused` and exit 3; the alert struck through; baseline CALIBRATING v2 | Dialog does not close: Touch ID cancelled; press Approve again |
| 8 | 3:45 | 1:28 (13 s) | "Now someone copies a device's flash and runs both. Neither knows the other exists. The server sees them collide." | C: `scripts/stage/05-clone.sh dev_stage_002`. Click dev_stage_002. Then "Restore (benign reset)", Touch ID. C: `scripts/stage/06-recover.sh dev_stage_002` | Both copies exit 3; REAUTH_REQUIRED panel with SEQUENCE_REGRESSION and two buttons; pinned SECURITY alert; after Restore, `RE-ENROLLED … boot_epoch=2` and 10 batches at 200 | No panel within 5 s: read 05-clone.sh output; if it says "re-enrolling once", wait for it; never run it twice in parallel |
| 9 | 4:30 | 1:41 (11 s) | "What is real today: KMS-signed certificates, mTLS on every request, live revocation, the three clone traps. What is designed only: a second CA for failover, multi-gateway eviction with Redis, a secure element for the device key. A clone that re-enrolls while the real device is off goes unnoticed until it comes back." | Scroll to the Audit log. | chain valid, 10 entries: passkey, provisioning, DEVICE_QUARANTINED, SECURITY_ANOMALY by system, DEVICE_RESTORED | Nothing to fix: this beat is talk |

## Rehearsal record

Rehearsed again in Phase 10a.1, on 2026-11-20 at 20:06 to 20:08 EST (2026-11-21 01:06 to 01:08 UTC), by
`scripts/rehearsal/rehearse.mjs`. That means headless Chrome at 1440x900, a CDP virtual authenticator for every Touch ID
step, the stage scripts above, and the demo profile with PT3M leaves, all after `scripts/stage/01-reset.sh`.

- T-15 steps (passkey, `dev_precheck_001` with 5 batches at 200, `dev_stage_002` enrolled) and `00-prestage.sh` (all
  PASS, `profiles=demo`) ran before the clock started.
- The automated run took **1:52** for all nine beats, because it does not talk. In Phase 10a, with PT4M leaves, it
  took 2:30.
- **Beat 5 no longer runs long.** The renewal is due 60 s after the leaf is issued (PT3M with the 60 s backdate,
  DECISIONS 83, 99). It landed at 1:16, exactly 60 s after beat 3's enroll; the 45 s in the table is the driver
  waiting, because it does not talk. Spoken, with the enroll at about 0:45, the rollover arrives at about 1:45, the
  planned time. In Phase 10a (PT4M) the wait was 85 s, and spoken it would have landed at about 2:25.
- Beat 8 needed one Protocol C refresh before cloning ("leaf renewal due in -29 s"): `dev_stage_002` was enrolled at
  T-15. The trap then fired on the clone's third batch, about 1 s after both copies started.
- After beat 7 the driver checks that the quarantined device's renewal log row shows the predecessor's final status
  with no countdown. It got `dev_stage_001 3C2D56A36999A355… 6D392D24038B5A0E…revoked 8:08:13 PM 8:08:13 PM
  REVOKED`: pass.
- Console messages: none. Page exceptions: none. Overflow: none, checked on every screenshot against the page width
  and against every panel's own bounds (no section scrolls sideways, no table or row past its panel's border).

| Beat | Started | Took | Result line |
|---|---|---|---|
| 1 problem | 0:00 | 4 s | dashboard landing, signed in |
| 2 trust chain | 0:04 | 9 s | CRL #1, 0 entries; 4 ACTIVE KMS keys |
| 3 provisioning + enroll | 0:13 | 2 s | `ENROLLED serial=3c2d56a36999a35526156a8a033a009ec84814d9 boot_epoch=1 not_after=2026-11-21T01:09:13Z` |
| 4 streaming | 0:15 | 16 s | baseline LOCKED after 16 batches |
| 5 rollover | 0:31 | 45 s | `RENEWED old=3C2D56A3… new=6D392D24… at=01:08:13.545Z`, `ACTIVATED … at=01:08:13.566Z` |
| 6 drift | 1:16 | 5 s | DRIFT alert "HR z=+4.8, HRV z=-3.8, SpO2 z=-2.6 over 4 resting batches" |
| 7 quarantine | 1:21 | 6 s | 2 certs revoked, 1 socket closed, 8.7 ms, 65 batches quarantined; simulator exit 3 |
| 8 clone + restore | 1:28 | 13 s | SEQUENCE_REGRESSION, both copies exit 3; restored; `RE-ENROLLED serial=679A794D… boot_epoch=2` |
| 9 close | 1:41 | 11 s | audit chain valid, 10 entries |
