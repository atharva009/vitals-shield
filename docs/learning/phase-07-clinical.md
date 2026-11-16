# Phase 7: The clinical engine (activity context, acute and drift alerts with lineage, compressed clock)

Commit: `5fc4a79` (feat(clinical): activity context, acute and drift engine with lineage, compressed clock scenarios).

*The spec's own disclaimer applies to everything in this note: z-score thresholds, the calibration window size, and
the acute physiological limits are configurable engineering defaults and have not been clinically validated (spec
Section 6).*

## 1. What this phase built and why

Until Phase 6 the server stored telemetry and classified each batch only as `ACCEPTED`, `SIGNAL_DEGRADED`, or
`REJECTED_IMPLAUSIBLE` (DECISIONS #46). Nothing read the numbers clinically, so the most interesting half of the spec
Section 6 quarantine CTE (resetting baselines and retracting alerts) had nothing to act on. Phase 7 builds the
engine that produces those baselines and alerts, so a quarantine now visibly removes their poisoned results:

- **Activity context** (`clinical/ActivityClassifier`): each batch is `RESTING` (cadence 0 and motion below 0.05 g,
  continuously for 5 minutes of measured time) or `EXERTION`.
- **Three alert kinds** (`clinical/ClinicalEvaluator`), all thresholds from `vitalsshield.clinical.*`
  (`ClinicalProperties`):
  - `LOW_PERFUSION_CRITICAL_ALERT`: 3 consecutive low-perfusion batches that also show a critical reading;
  - `ACUTE_PHYSIOLOGICAL_ALERT`: context-aware limits (resting HR, exertion HR by age, SpO2), deduplicated for
    5 minutes per condition (DECISIONS #71);
  - `POTENTIAL_PHYSIOLOGICAL_DRIFT`: 2 of 3 z-scores past their limits on 4 resting batches in a row, against the
    patient's own baseline.
- **A personal resting baseline**: the first 10 (demo) or 30 (default) trusted resting batches give a mean and SD per
  metric, after which the baseline is `LOCKED` (DECISIONS #72).
- **Lineage on every alert**: `triggering_batch_ids` and, for drift, `baseline_version`. The quarantine CTE uses
  exactly these to retract what was built on quarantined data.
- **Evaluation after ingest, in its own transaction** (DECISIONS #69), queued per assignment, under a global lock
  order (DECISIONS #70) written at the top of every class that opens such a transaction.
- **Alert actions**: acknowledge and resolve, passkey session, audited (DECISIONS #76).
- **An append-only audit log** enforced by Postgres triggers (DECISIONS #75), and `scripts/reset-demo-state.sh`,
  which drops the Compose Postgres volume instead of deleting rows.
- **`needs_attention`** on the overview for a device whose certificate was revoked but whose quarantine did not commit
  (DECISIONS #77).
- **The simulator's compressed clock, persisted** (DECISIONS #74), five scenarios, `--script`, and live switching with
  `simulator scenario --set`.
- **Dashboard**: a baseline card, activity and z-scores in the telemetry table, an alerts panel, alert tiles, and an
  amber needs-attention chip.

Deviations and additions beyond the brief, each recorded in DECISIONS: the evaluator locks the assignment row
`FOR NO KEY UPDATE`, not `FOR UPDATE` (added to #70, explained in section 2); the evaluator runs on its own
boundedElastic scheduler, not the shared one (section 9); and a streak whose stored batch ids are no longer all
trusted starts over (section 5).

## 2. Concept primers

### Why a personal resting baseline beats population thresholds

A population threshold says "a resting heart rate above 100 is high". That is true on average and wrong for many
people: a trained athlete may rest at 45, someone on a beta blocker even lower, someone else at 85 every day. A fixed
threshold misses a change from 45 to 80 (a large change for that person) and keeps flagging a healthy 95.

A personal baseline asks a different question: is this person different from how *they* usually are? It needs a few
trusted measurements of the person at rest first, and from them we learn their own normal value and their own
variation. Drift is then measured in units of that variation. The spec keeps population-style limits too, for
emergencies that do not need a baseline (the acute rules: resting HR at or above 140, SpO2 at or below 90). Both
exist because they answer different questions: "is this dangerous right now?" and "is this person slowly changing?".

### Mean, sample SD, and z-scores, with a worked example from real batches

These are the 10 calibration batches of `dev_clinical_001` from the exit-criteria run (section 7), read back from
`telemetry_records` through `calibration_batch_ids`:

| seq | HR | HRV (ms) | SpO2 (%) |
| ---: | ---: | ---: | ---: |
| 6 | 65 | 53.60 | 98.40 |
| 7 | 64 | 45.53 | 97.59 |
| 8 | 64 | 48.22 | 97.19 |
| 9 | 67 | 51.67 | 97.20 |
| 10 | 68 | 54.36 | 98.80 |
| 11 | 66 | 46.29 | 98.00 |
| 12 | 67 | 48.98 | 97.60 |
| 13 | 63 | 49.80 | 98.72 |
| 14 | 64 | 52.49 | 98.32 |
| 15 | 62 | 54.42 | 97.52 |

**Mean** of HR: (65 + 64 + 64 + 67 + 68 + 66 + 67 + 63 + 64 + 62) / 10 = 650 / 10 = **65**.

**Sample standard deviation**: subtract the mean from each value, square, add up, divide by n - 1, take the square
root. The differences are 0, -1, -1, 2, 3, 1, 2, -2, -1, -3; their squares add up to 0 + 1 + 1 + 4 + 9 + 1 + 4 + 4 +
1 + 9 = 34; 34 / 9 = 3.778; the square root is **1.9437**. Dividing by n - 1 rather than n corrects for the fact that
the mean itself was estimated from the same 10 values, which makes the plain average of squared differences slightly
too small. The server stored exactly these: `ref_hr_mean = 65`, `ref_hr_sd = 1.9436506316151`. For HRV it stored
50.536 and 3.2594, for SpO2 97.934 and 0.5992.

**z-score**: how many SDs a value is from the mean, `z = (x - mean) / SD`. The first drift batch (seq 17) had HR 86,
HRV 31.34, SpO2 95.06:

```
z_HR   = (86    - 65)     / 1.9437 = +10.80     limit: >= +2.0  -> breach
z_HRV  = (31.34 - 50.536) / 3.2594 =  -5.89     limit: <= -1.8  -> breach
z_SpO2 = (95.06 - 97.934) / 0.5992 =  -4.80     limit: <= -1.5  -> breach
```

At least 2 of 3 breach, so the batch is a drift breach. Seqs 18, 19, 20 gave (+10.80, -5.40, -3.44), (+7.72, -6.88,
-4.13), (+7.72, -6.39, -4.46). After the fourth, the alert fired with the mean z-scores of those 4 batches: "Drift vs
baseline v1: HR z=+9.3, HRV z=-6.1, SpO2 z=-4.2 over 4 resting batches". The directions matter: a higher resting heart
rate, a lower heart rate variability, and a lower oxygen saturation are each the worrying direction; the opposite
directions are not counted.

### Why SD floors exist

If the calibration batches happen to be very similar, the SD is tiny, and every later batch, however ordinary, gets a
huge z-score. In the extreme case of 10 identical heart rates the SD is 0 and z is a division by zero. A floor sets a
minimum SD per metric (HR 1.0 bpm, HRV 1.0 ms, SpO2 0.5 percentage points, DECISIONS #72), roughly the resolution and
normal noise of the sensor, so a breach always means a change larger than measurement noise.
`CalibrationStatsTest.floorAppliedWhenAllValuesAreEqual` checks it.

### Why only resting batches calibrate

Heart rate during exercise depends on the exercise, not on the person's underlying state. If walking batches went into
the baseline, its mean would be higher and its SD much larger, so real resting drift would hide inside the inflated
SD, and the baseline would depend on what the patient happened to do during the first hour. Only `ACCEPTED`
batches classified `RESTING` calibrate. Two more exclusions: `SIGNAL_DEGRADED` batches (the optical signal was poor,
so the numbers are unreliable), and any batch that met an acute condition, even one whose alert was deduplicated
(DECISIONS #72). The last one stops an emergency from becoming part of "normal".

The 5-minute sustain rule makes "resting" mean resting: the first still batch after activity starts a clock
(`resting_since`), and only once 5 minutes of still batches have passed are they `RESTING`. Before that they are
`EXERTION` ("not yet sustained").

### Streaks and dedupe, and why alert storms are a clinical safety problem too

A single bad reading is often an artifact: a loose strap, a hand moving. Requiring several in a row (3 for low
perfusion, 4 for drift) trades a few minutes of delay for far fewer false alerts.

Deduplication matters for the opposite reason. A patient whose heart rate stays at 155 produces a qualifying batch
every minute. Without dedupe that is 60 identical alerts an hour. Clinicians who receive streams of duplicate alerts
learn to dismiss them ("alarm fatigue"), and then miss the one that is new. So each rule fires once per episode
(DECISIONS #71): low perfusion fires when its streak reaches 3 and not again until the streak resets; an acute
condition is suppressed while an open alert for the same condition and assignment has a triggering batch measured in
the last 5 minutes; drift fires at 4 and starts counting again from zero.

### Lineage: triggering_batch_ids and baseline_version

Every alert records what it was computed from. `triggering_batch_ids` lists the batches: one for an acute alert,
three for low perfusion, four for drift. A drift alert also records `baseline_version`, because it was computed
against a specific baseline, and that baseline was computed from its own batches (`calibration_batch_ids`). The schema
enforces this with `chk_alert_baseline_lineage`: a drift alert must have a baseline version, any other alert must not.

The point is that a conclusion can be traced back to its evidence, and withdrawn when the evidence is withdrawn.

### Exactly what retraction removes and what it keeps

A confirmed-compromise quarantine marks every `ACCEPTED` or `SIGNAL_DEGRADED` batch of the device inside the lookback
window as `QUARANTINED` (spec Section 6). Then, in the same statement:

- **A baseline is reset** if any of its calibration batches was quarantined: state `CALIBRATING`, version + 1,
  calibration ids and `ref_*` cleared, and (Phase 7) the four streak columns zeroed. The patient's baseline will be
  rebuilt from new, trusted data.
- **An alert is retracted** (`RETRACTED_BY_QUARANTINE`, `retracted_at` set) if it is `ACTIVE` or `ACKNOWLEDGED` and
  either one of its triggering batches was quarantined, or it is a drift alert computed against the baseline version
  that was just reset (even if its own four batches were outside the window: the baseline itself was poisoned).

It keeps everything else: alerts whose batches are all outside the window, alerts with no telemetry lineage (security
alerts), already resolved alerts, and all rows themselves. Nothing is deleted: a quarantined batch is still in
`telemetry_records` with its JWS, and a retracted alert still has its explanation. `QuarantineRetractionIT` checks
each of these cases.

### The compressed clock, and why dual-timestamp quarantine needs both timestamps

The clinical rules talk in minutes: 5 minutes of rest, 4 consecutive one-minute batches. A live demo cannot wait an
hour for a baseline to calibrate. The simulator therefore stamps each batch with a `measured_at` 60 seconds after the
previous one, starting 12 hours in the past, never later than now (DECISIONS #6, #74). One batch per real second is
one minute of clinical time, so the demo's 16 resting batches (5 to sustain rest, 10 to calibrate, 1 spare) take 16
seconds. Phase 7 persists the last `measured_at` in `state.json`, so a restarted simulator continues the same timeline
instead of jumping back 12 hours.

This is exactly the situation the spec's dual-timestamp rule is for. A wearable can upload hours-old measurements
after being offline, and under the compressed clock every batch claims to have been measured about 12 hours ago. A
quarantine window of "the last 10 minutes" judged on `measured_at` alone would find nothing; judged on `ingested_at`
alone, it would miss old poisoned data uploaded long before. The CTE takes a batch if *either* timestamp is inside
the window. In the exit-criteria run, every batch has `measured_at` around 09:00 UTC and `ingested_at` around
21:00 UTC the same day; a quarantine with lookback 10 minutes run right afterwards catches them by `ingested_at`.

### Lock ordering and deadlocks, with the actual cycle this phase would have hit

Phase 6.1 introduced the rule for the audit lock: take it last. Phase 7 adds transactions that lock several tables at
once and generalizes it to one global order (DECISIONS #70):

```
devices -> telemetry_records -> patient_device_assignments -> clinical_alerts -> audit advisory lock
```

Here is the deadlock the natural first implementation would have had. Suppose the evaluator first locked the batch it
was about to evaluate, then checked the device:

```
Evaluator E: SELECT ... FROM telemetry_records WHERE batch_id = B FOR UPDATE      (holds row B)
Quarantine Q: SELECT ... FROM devices WHERE device_id = D FOR UPDATE              (holds device D)
Quarantine Q: sanitize CTE: UPDATE telemetry_records ... includes row B           (waits for E)
Evaluator E: SELECT ... FROM devices WHERE device_id = D FOR KEY SHARE            (waits for Q)
```

Each waits for the other; Postgres aborts one after a second with SQLSTATE 40P01. With the global order, the
evaluator locks the device first, so either it gets the device lock before the quarantine (and the quarantine waits
for it to finish) or after the quarantine has committed (and it sees `QUARANTINED` and stops). Neither can be holding
something the other needs while waiting. `LockOrderIT` runs this race 20 times.

### FOR KEY SHARE vs FOR UPDATE

Postgres has four row-lock strengths. Which pairs conflict is what makes the order above cheap:

| held \ requested | FOR KEY SHARE | FOR SHARE | FOR NO KEY UPDATE | FOR UPDATE |
| :--- | :---: | :---: | :---: | :---: |
| FOR KEY SHARE | | | | conflict |
| FOR SHARE | | | conflict | conflict |
| FOR NO KEY UPDATE | | conflict | conflict | conflict |
| FOR UPDATE | conflict | conflict | conflict | conflict |

- An `UPDATE` that does not change a key column takes `FOR NO KEY UPDATE`. The ingest CTE's update of the `devices`
  row is one.
- A foreign key check takes `FOR KEY SHARE` on the referenced row: inserting a telemetry row locks its device and
  assignment rows this way.
- The evaluator takes `FOR KEY SHARE` on the device. It does not conflict with the ingest CTE, so evaluating batch N
  never delays ingesting batch N + 1. It does conflict with quarantine's `FOR UPDATE`, which is the one interaction we
  need.
- The evaluator locks the assignment `FOR NO KEY UPDATE`, not `FOR UPDATE` as first briefed. It still serializes two
  evaluations of the same assignment and conflicts with the quarantine CTE's update of the assignment. But `FOR
  UPDATE` would also conflict with the `FOR KEY SHARE` an ingest's INSERT takes on the same assignment through the
  foreign key, so every ingest would wait for the evaluation of the previous batch.

### Append-only audit enforced by a trigger

The Phase 6 hash chain detects edits; it does not prevent them. Phase 7 adds prevention for everyone below the table
owner: V5 creates a function that raises `security_audit_log is append-only` and attaches it as a `BEFORE UPDATE OR
DELETE ... FOR EACH ROW` trigger and a `BEFORE TRUNCATE ... FOR EACH STATEMENT` trigger. Any UPDATE, DELETE, or
TRUNCATE fails, whatever its WHERE clause, and the transaction is aborted. The two defences cover each other: the
table owner or a superuser can `ALTER TABLE ... DISABLE TRIGGER` and then edit, which the hash chain then reports
(`AuditChainIT` does exactly this), and the S3 Object Lock anchor (still "Designed") would cover a rewrite of the
whole chain.

One consequence: the Phase 6.1 reset step that deleted audit rows is no longer possible. Demo resets now drop the
whole Compose Postgres volume (`scripts/reset-demo-state.sh`, DECISIONS #75).

### The spec's disclaimer: these thresholds are not clinically validated

Spec Section 6 says it directly: the z-score thresholds, the calibration window, and the acute limits are
configurable engineering defaults and have not been clinically validated. Every number lives in
`vitalsshield.clinical.*` with the spec value as its default (`ClinicalPropertiesTest` checks the bound defaults equal
`ClinicalProperties.defaults()`), so a clinical team could tune them without a code change. What this phase
demonstrates is the security property: whatever the thresholds, results computed from data later found to be
compromised are traceable and withdrawn.

## 3. How it works in our code

### Ingest to evaluation

```
device --mTLS--> TelemetryIngestService.ingestBlocking         (boundedElastic)
                   classify(plausibility, perfusion)            ClinicalProperties bounds
                   spec Section 5 CTE (autocommit)              -> 200 to the device
                   if a new row and not REJECTED_IMPLAUSIBLE:
                     ClinicalEvaluator.submit(device, assignment, batch)   (non-blocking)
                                   |
         per-assignment queue:  tail(assignment) = tail.thenRunAsync(evaluate, "clinical-eval" scheduler)
                                   |
         evaluate: one transaction
           1 devices        FOR KEY SHARE     not ACTIVE -> stop
           2 telemetry row  FOR UPDATE        not ACCEPTED/SIGNAL_DEGRADED, or evaluated -> stop
           3 assignment     FOR NO KEY UPDATE
           4 activity (resting_since, sustain, regression reset)
           5 SIGNAL_DEGRADED: low-perfusion streak            | ACCEPTED: reset that streak,
                                                              |   6 acute + dedupe
                                                              |   7 calibration (CALIBRATING)
                                                              |   8 drift (LOCKED, RESTING)
           UPDATE assignment; INSERT clinical_alerts; UPDATE telemetry (activity_context, clinical_evaluated_at)
```

A failed evaluation rolls back, increments `clinical.evaluation_failures`, and leaves `clinical_evaluated_at` NULL;
the dashboard shows such rows as "unevaluated", and the overview counts them.

### Calibration to lock

```
batch:   1  2  3  4  5 |  6  7  8  9 10 11 12 13 14 15 | 16 ...
activity EXERTION x5   |  RESTING ------------------->
         (still, not   |  calibration_batch_ids grows 1..10
          sustained)   |  at 10: mean + sample SD per metric, SD floors,
                       |  ref_* set, baseline_state LOCKED (version stays 1)
```

### Drift alert

```
LOCKED v1                 breach?  drift_breach_streak   drift_breach_batch_ids
seq 16 resting            no       0                     {}
seq 17 drift              yes      1                     {17}
seq 18 drift              yes      2                     {17,18}
seq 19 drift              yes      3                     {17,18,19}
seq 20 drift              yes      4 -> fire, reset 0    {}    alert: DRIFT, v1, ids {17,18,19,20}
seq 21 drift              yes      1                     {21}
seq 22 acute (HR 156)     no*      0                     {}    alert: ACUTE RESTING_HR_HIGH, ids {22}
seq 23 acute (HR 154)     no*      0                     {}    RESTING_HR_HIGH deduplicated
* only z_HR breaches; 1 of 3 is not a drift breach
```

### Quarantine retraction, re-provision, recalibration

```
before:  baseline LOCKED v1 (calibration {6..15})   alerts: DRIFT v1 ACTIVE, ACUTE ACTIVE
quarantine (step-up, lookback covers the batches):
  revoke cert, evict sockets  ->  tx: devices FOR UPDATE; QUARANTINED; tokens revoked;
  CTE: batches QUARANTINED -> baseline CALIBRATING v2, ids {}, streaks 0 -> alerts RETRACTED; audit append
queued evaluations: devices row says QUARANTINED -> skipped, no alert
re-provision (passkey) -> Protocol A -> boot_epoch 2, same assignment
new batches: activity restarts (measured_at went backwards, DECISIONS #69), then calibration under v2
```

`ClinicalRetractionE2E` runs this whole sequence on every regression gate.

### The lock order across the codebase

```
                       devices   telemetry   assignments   alerts   audit lock
ClinicalEvaluator      KEY SHARE  UPDATE      NO KEY UPD    INSERT       -
QuarantineService      UPDATE     (CTE)  ->   (CTE)    ->   (CTE)    -> last
AlertService              -          -            -         UPDATE   -> last
ProvisioningService    INSERT        -         INSERT/UPD      -     -> last
StepUpService.restore  UPDATE        -            -            -     -> last
EnrollmentService      UPDATE        -         read only       -        -
ingest CTE             NO KEY UPD  INSERT     (FK KEY SHARE)   -        -
```

Every row reads left to right, so no transaction ever waits for a lock to its left while holding one to its right.

## 4. Data model

V5 (`V5__clinical_engine.sql`):

| Table | Column | Meaning |
| :--- | :--- | :--- |
| `patient_device_assignments` | `resting_since` | measured_at of the first still batch of the current still run; NULL when not still |
| | `degraded_critical_streak`, `degraded_critical_batch_ids` | low-perfusion streak and its last 3 batch ids |
| | `drift_breach_streak`, `drift_breach_batch_ids` | drift streak and its batch ids |
| | `last_evaluated_measured_at` | measured_at of the last evaluated batch, for the regression rule (DECISIONS #69) |
| `telemetry_records` | `activity_context` | `RESTING`, `EXERTION`, or NULL (not evaluated) |
| | `clinical_evaluated_at` | NULL means "not evaluated" |
| `clinical_alerts` | `condition_code` | `RESTING_HR_HIGH`, `RESTING_HR_LOW`, `EXERTION_HR_HIGH`, `SPO2_LOW`, `LOW_PERFUSION_CRITICAL`, `DRIFT`; the dedupe key |
| `security_audit_log` | two triggers | reject UPDATE, DELETE, TRUNCATE |

The lineage columns were already in V1 (spec Section 7): `clinical_alerts.triggering_batch_ids UUID[]` with a GIN
index (the CTE's `&&` overlap test uses it), `clinical_alerts.baseline_version` with the `chk_alert_baseline_lineage`
check, and `patient_device_assignments.calibration_batch_ids` with `baseline_state` and `baseline_version`. Phase 7 is
the first phase that writes them.

Why streak state is on the assignment and not in memory (DECISIONS #68): it survives a restart, it is updated under
the same row lock that serializes evaluations, and the quarantine CTE can reset it in the same statement that resets
the baseline.

## 5. Security reasoning

**How poisoned data is kept out of baselines and alerts.** Telemetry only reaches the engine after the Phase 4 chain
of checks: an mTLS certificate that is not revoked, a JWS signed by that certificate's key, a fresh sequence number,
plausibility bounds. The engine adds:

- only `ACCEPTED` `RESTING` batches calibrate; degraded, exertion, and acute batches never do;
- the baseline locks after its window and does not keep adapting, so a slow drift cannot drag the baseline along with
  it;
- when a device is confirmed compromised, the quarantine resets every baseline that used any batch in the window and
  retracts every alert built on those batches or on that baseline, in the same transaction as the state change
  (DECISIONS #42, #67);
- evaluations still queued at that moment see the device is not ACTIVE and create nothing;
- a streak whose stored batch ids are no longer all trusted (for example, batches quarantined while the baseline was
  computed from older data) starts over, so a later alert can never list a quarantined batch as evidence.
  `LockOrderIT` checks after every repetition that no unretracted alert has a quarantined triggering batch.

**What is not defended.**

- *A compromised device that sends plausible lies.* If an attacker controls the device key from the start, it can send
  well-signed, plausible, resting-looking numbers, and the engine will build a false baseline from them. Signatures
  prove which device sent data, not that the data is true. The defence is detection (anomaly review, the device
  attestation chain) followed by quarantine, which then removes everything built on that window. Data outside the
  chosen lookback window stays trusted.
- *Clinical validity.* The thresholds are engineering defaults (spec Section 6). Nothing here has been validated on
  patients, and the engine does not replace clinical judgment.
- *The dashboard as an alerting system.* Alerts appear in a panel that polls once a second; there is no paging or
  escalation.
- *Lost evaluations on a crash.* A batch accepted just before a crash stays unevaluated (visible on the dashboard);
  there is no re-queue at startup.

## 6. Design decisions (DECISIONS #68 to #77)

| # | Decision | Alternatives that lost |
| :--- | :--- | :--- |
| 68 | Streak state on `patient_device_assignments`, activity on each batch, `condition_code` on alerts | In memory (lost on restart, unreachable by the quarantine CTE); a separate streak table (one more lock in the order) |
| 69 | Evaluate after the ingest commit, in its own transaction, in ingestion order per assignment | Inside the ingest CTE (changes spec Section 5 SQL, slows every ingest, and couples ingest failures to clinical bugs); ordering by measured_at (an old upload would rewrite streaks after the fact) |
| 70 | One global lock order; KEY SHARE on devices; NO KEY UPDATE on the assignment | FOR UPDATE everywhere (evaluations would block ingest); no device lock in evaluation (an alert could be created after a quarantine committed) |
| 71 | Fire once per episode (streak or 5-minute window) | Every qualifying batch (alarm fatigue); a global cooldown per device (one condition would hide another) |
| 72 | Resting, non-acute, ACCEPTED batches; sample SD with floors; 30 default, 10 demo | All accepted batches (exercise inflates the SD); population SD (n) (too small for a 10-sample window) |
| 73 | Exertion and degraded batches neither count nor reset the drift streak | Resetting on exertion (a 30-second walk would hide drift forever); counting them (exercise HR would trigger drift) |
| 74 | Persist the last measured_at; continue from it | Recompute now - 12 h on each launch (measured_at jumps backwards on every restart) |
| 75 | Database trigger makes the audit log append-only; resets drop the volume | Revoking UPDATE/DELETE grants (the app connects as the owner in this build); deleting rows in resets (now impossible by design) |
| 76 | Acknowledge and resolve need a session and are audited; no step-up | Step-up per acknowledgement (a Touch ID prompt for every alert slows clinicians and protects little: these actions change status, not data) |
| 77 | `needs_attention` when ACTIVE with only revoked certificates | Undoing the revocation when the quarantine fails (re-opens access to a device believed compromised) |

## 7. Verify it yourself

Real outputs from the exit-criteria runs (bootRun with `--spring.profiles.active=local`, webauthn mode).

**Reset** (exit criterion 5), with the server stopped:

```
$ scripts/reset-demo-state.sh
Compose Postgres volume: vitals-shield_pgdata
 Container vitals-shield-postgres-1 Stopped
 Container vitals-shield-postgres-1 Removed
vitals-shield_pgdata
 Volume vitals-shield_pgdata Created
 Container vitals-shield-postgres-1 Started
waiting for postgres to become healthy..... ok

Reset complete:
  - Compose Postgres volume vitals-shield_pgdata dropped and recreated (empty; Flyway migrates it on the next boot)
  - simulator-state/, var/admin/, var/devseed/ deleted
  - LocalStack untouched: the next boot finds no ACTIVE kms_keys rows and rebuilds the CA hierarchy (REBUILT)
```

Then `./gradlew :server:bootRun --args='--spring.profiles.active=local'` logged:

```
Migrating schema "public" to version "1 - baseline"
Migrating schema "public" to version "2 - issued serials"
Migrating schema "public" to version "4 - passkey purpose"
Migrating schema "public" to version "5 - clinical engine"
Hierarchy reconciliation: REBUILT
Listener admin bound on /127.0.0.1:8445
Listener admin-ipv6 bound on /[0:0:0:0:0:0:0:1]:8445
$ curl -s http://localhost:8445/api/v1/admin/auth/status
{"mode":"webauthn","passkeys_registered":0,"clinician_id":null}
```

**Clinical run** (exit criterion 6):

```
$ ./gradlew -q :server:seedDemoDevice --args='--device-id dev_clinical_001'
... Passkey registered for dev-seed-clinician (credential l2yZgwZq..., anchor signed with KMS Key #4)
BOOTSTRAP_TOKEN=h9uY...of4Y (shortened)
$ simulator factory-wipe --device-id dev_clinical_001
FACTORY_WIPED simulator-state/dev_clinical_001
$ simulator enroll --device-id dev_clinical_001 --token <token>
ENROLLED serial=2ed4e9af9446efdb6e9f66e21a6d47bc4c0907 boot_epoch=1 not_after=2026-11-17T08:57:49Z
$ simulator run --device-id dev_clinical_001 --script "resting:16,drift:5,acute:2" --count 23
SCENARIO resting
SENT seq=1 batch=9d6934e1 status=200 rtt_ms=136 measured_at=2026-11-16T08:58:56.259735Z scenario=resting trust_state=ACCEPTED
SENT seq=2 batch=76139314 status=200 rtt_ms=21 measured_at=2026-11-16T08:59:56.259735Z scenario=resting trust_state=ACCEPTED
...
SENT seq=16 batch=605c67b9 status=200 rtt_ms=20 measured_at=2026-11-16T09:13:56.259735Z scenario=resting trust_state=ACCEPTED
SCENARIO drift
SENT seq=17 batch=69110949 status=200 rtt_ms=19 measured_at=2026-11-16T09:14:56.259735Z scenario=drift trust_state=ACCEPTED
...
SENT seq=21 batch=93b5de10 status=200 rtt_ms=20 measured_at=2026-11-16T09:18:56.259735Z scenario=drift trust_state=ACCEPTED
SCENARIO acute
SENT seq=22 batch=6981e853 status=200 rtt_ms=16 measured_at=2026-11-16T09:19:56.259735Z scenario=acute trust_state=ACCEPTED
SENT seq=23 batch=1c6c9c5f status=200 rtt_ms=13 measured_at=2026-11-16T09:20:56.259735Z scenario=acute trust_state=ACCEPTED
```

`--count 23` makes the run end after the script; without it the simulator holds the last scenario until stopped.
The run was made at 15:58 local (20:58 UTC): measured_at starts 12 hours earlier and advances one minute per batch.

```
$ psql -c "select alert_type, condition_code, alert_status, baseline_version, cardinality(triggering_batch_ids)
           from clinical_alerts where device_id='dev_clinical_001' order by created_at"
          alert_type           | condition_code  | alert_status | baseline_version | cardinality
-------------------------------+-----------------+--------------+------------------+-------------
 POTENTIAL_PHYSIOLOGICAL_DRIFT | DRIFT           | ACTIVE       |                1 |           4
 ACUTE_PHYSIOLOGICAL_ALERT     | RESTING_HR_HIGH | ACTIVE       |                  |           1

$ psql -c "select baseline_state, baseline_version, cardinality(calibration_batch_ids), ref_hr_mean, ref_hr_sd
           from patient_device_assignments where device_id='dev_clinical_001'"
 baseline_state | baseline_version | cardinality | ref_hr_mean |    ref_hr_sd
----------------+------------------+-------------+-------------+-----------------
 LOCKED         |                1 |          10 |          65 | 1.9436506316151

 explanation_summary
---------------------------------------------------------------------------------
 Drift vs baseline v1: HR z=+9.3, HRV z=-6.1, SpO2 z=-4.2 over 4 resting batches
 Resting heart rate 156 bpm for 5+ min (limit 140)

 sequence_number | activity_context | heart_rate_bpm | hrv_rmssd_ms | spo2_pct
-----------------+------------------+----------------+--------------+----------
               5 | EXERTION         |             65 |        50.91 |    98.79
               6 | RESTING          |             65 |         53.6 |     98.4
```

Seq 5 is still but only 4 minutes into the rest, so it is EXERTION; seq 6 is the first RESTING batch and the first
calibration batch. The second acute batch (seq 23, HR 154) was deduplicated.

**The trigger** (exit criterion 7):

```
$ psql -c "DELETE FROM security_audit_log"
ERROR:  security_audit_log is append-only
CONTEXT:  PL/pgSQL function security_audit_log_append_only() line 3 at RAISE
```

To try live switching, run the simulator without `--script` and, in another terminal,
`simulator scenario --device-id dev_clinical_001 --set drift`; the running simulator prints `SCENARIO drift` before its
next batch.

## 8. How the tests prove it

| Test | Property proved |
| :--- | :--- |
| `ActivityClassifierTest` | motion 0.049 vs 0.05, cadence 0 vs 1; 5:00 sustained vs 4:59; a measured_at regression restarts the clock; the 6th still batch is the first RESTING |
| `AcuteRulesTest` | each condition at its boundary; age 41 for 1985 in 2026 gives 170.3; explanation text |
| `DegradedCriticalStreakTest` | 2 then reset does not fire; 3 fires, 4 and 5 do not; a reset then 3 fires again; the 3 ids are the trigger |
| `CalibrationStatsTest` | sample SD equals hand-computed values; floors when all values are equal; acute-triggering batches are not eligible |
| `DriftRuleTest` | 2 of 3 required, any single breach is not enough; 4 fires and resets; exertion neither counts nor resets; a non-breaching resting batch resets |
| `AlertDedupeTest` | inside vs outside the 5-minute window; condition codes are independent |
| `ClinicalPropertiesTest` | bound defaults equal the spec values; overrides bind; allowed alert transitions |
| `ScenarioTest`, `SimulatorStateStoreTest` | generator ranges, seeded determinism, script order and hold, compressed clock rules, measured_at persisted with the sequence number across a reopen |
| `ClinicalEngineIT` (7 tests) | through the real ingest endpoint: rest sustain, lock at exactly 10 with the expected `ref_*`, one drift alert on v1 with 4 ids, acute dedupe and exclusion from calibration, one low-perfusion alert, exertion between breaches, implausible batches not evaluated |
| `QuarantineRetractionIT` | drift, in-window acute, and low-perfusion alerts retracted; the 120-minute-old acute and the security alert untouched; baseline CALIBRATING v2 with empty ids and zeroed streaks; 3 held evaluations released after the quarantine create no alert |
| `LockOrderIT` | 20 repetitions of 8 parallel ingests plus a mid-stream quarantine: all quarantines 200, no 40P01, no evaluation failure, no unretracted alert with a quarantined batch |
| `AlertActionsIT` (7 tests) | ack then resolve, direct resolve, illegal transitions 409, retracted is final, 404 and 400, no session 401, no Origin 403, DEV_SEED gets no session; audit entries and chain; the alerts list and overview counts |
| `AuditImmutabilityIT` (5 tests) | UPDATE, DELETE, TRUNCATE fail with the trigger message; append still works; no SQL string under `server/src/main` edits the table |
| `QuarantineAuditAtomicityIT.failureInsideAuditAppendRollsBackQuarantine` | a throw inside `AuditLog.append` (after its INSERT) leaves device, telemetry, baseline, alerts, and audit unchanged while the certificate stays revoked; `needs_attention` is set; the retry succeeds and clears it |
| `ClinicalRetractionE2E` | lock at 10, drift alert, step-up quarantine retracts it and resets to v2, re-provision and re-enroll calibrate again under v2 from boot epoch 2 |

Unlike the Phase 6.1 atomicity test, the audit-append fault test does discriminate: with the old design (audit in a
separate transaction after the quarantine) the device would be QUARANTINED after the failure, and the snapshot
comparison would fail.

`LockOrderIT` output from the final run (abridged):

```
LOCK_ORDER rep=1 accepted=55 evaluated=7 alerts=4 retracted=4 quarantined_batches=55
LOCK_ORDER rep=2 accepted=39 evaluated=5 alerts=2 retracted=2 quarantined_batches=41
...
LOCK_ORDER rep=20 accepted=47 evaluated=5 alerts=2 retracted=2 quarantined_batches=51
LOCK_ORDER deadlocks before=0 after=0
```

In each repetition only 4 to 7 of about 45 batches were evaluated before the quarantine committed: evaluation is one
at a time per assignment and the burst arrives in about 100 ms. The remaining evaluations ran after the commit and
stopped at step 1. `quarantined_batches` can exceed `accepted` because a batch can commit while its response is lost
to the socket eviction.

## 9. Gotchas hit during this phase

- **A Phase 4 test started timing out, only in the full integration suite.** `ConcurrentDuplicateIT` (20 parallel
  ingests) got `SocketTimeoutException: Read timed out` twice in a row in `./gradlew integrationTest`, and passed when
  run alone or with its neighbours. Spring keeps the application contexts of earlier test classes cached, but their
  Testcontainers Postgres is stopped when the class ends. Evaluations still queued in those dead contexts each waited
  up to 30 s for a database connection while holding a thread of the JVM-wide shared boundedElastic scheduler, the
  same one that runs ingest. The evaluator now has its own boundedElastic scheduler (at most 4 threads, disposed with
  the context). The full suite then passed (175 tests). The same isolation matters in production: a slow database
  now delays clinical evaluations, not request handling.
- **The new trigger broke the Phase 6 tamper test.** `AuditChainIT.tamperingOnePayloadBreaksTheChainAtThatEntry`
  edits a row on purpose. It now disables the trigger first (as a table owner could), which also demonstrates why the
  hash chain is still needed.
- **A z-score exactly at its limit is not reliably at its limit.** A drift unit test used HRV 44.6 against mean 50 and
  SD 3 to hit z = -1.8 exactly; in floating point (44.6 - 50) / 3 is not exactly -1.8, so the "breach" was not one.
  The boundary tests for the activity and acute rules use integers and exact binary fractions; the drift test uses
  values clearly past the limit.
- **A test's future timestamp was refused by the validator.** `ClinicalStream` stepped measured_at forward past the
  current time and the ingest answered `400 PAYLOAD_INVALID MEASURED_AT_AFTER_TRANSMITTED_AT` (measured_at may be at
  most 1 minute after transmitted_at). This is also why the compressed clock is capped at now.
- **An exertion batch costs five more batches of rest.** It clears `resting_since`, so the still batches after it are
  EXERTION ("not yet sustained") for 5 minutes and do not count toward drift either. The drift streak survives
  (DECISIONS #73), but it resumes only after those five; `ClinicalEngineIT.exertionBetweenDriftBreachesNeitherResetsNorCounts`
  asserts exactly that sequence.

## 10. Judge Q&A

**Q: How do you stop a compromised sensor from poisoning the baseline?**
A: In layers. Only data from a device with a valid, unrevoked certificate, signed by that certificate's key, with a
fresh sequence number, inside hardware plausibility bounds, reaches the engine. Of that, only good-signal resting
batches that did not trigger an acute alert calibrate, and the baseline locks after its window, so it cannot be
dragged slowly. When a compromise is confirmed, the quarantine marks the window's batches QUARANTINED and, in the same
transaction, resets any baseline that used them (CALIBRATING, version + 1) and retracts every alert whose evidence
includes them or that was computed against the reset baseline. A device that lies plausibly from day one, under a key
the attacker controls, can still build a false baseline: signatures prove who sent the data, not that it is true.
Quarantine then limits the damage to what can be traced, and the lineage columns make that tracing exact.

**Q: Are these thresholds clinically validated?**
A: No. The spec says so in Section 6: the z-score thresholds, the calibration window, and the acute limits are
configurable engineering defaults that have not been clinically validated. They are all in `vitalsshield.clinical.*`
so a clinical team could set them. The property this project demonstrates is not clinical accuracy; it is that
clinical results are traceable to signed evidence and withdrawn when that evidence is withdrawn.

**Q: Why not just delete the bad data?**
A: Because the record of what happened matters. Quarantined batches keep their JWS so they can be examined later, and
retracted alerts keep their explanation, their evidence, and a retraction time, so a clinician who saw an alert can see
why it disappeared. Deleting would also make "what did the system believe at 14:00?" unanswerable. The audit log goes
further: it cannot be edited at all, enforced by a database trigger.

**Q: Your evaluation is asynchronous. Can an alert appear after the quarantine?**
A: No. Every evaluation takes a key-share lock on the device row before anything else, and the quarantine takes an
exclusive lock on that row first. So an evaluation either finishes before the quarantine starts its transaction (its
alert is then visible to the sanitize statement and retracted if its batches are in the window) or starts after the
quarantine committed and sees the device is not ACTIVE. `QuarantineRetractionIT` holds three evaluations until after
the quarantine and checks that they create nothing; `LockOrderIT` races the two 20 times.

**Q: How do you avoid deadlocks with that many locks?**
A: One global order for every transaction: devices, then telemetry, then assignments, then alerts, then the audit
lock. If everyone acquires in the same order, no two transactions can each hold what the other wants. The order is
written at the top of every class that opens such a transaction. We also picked the weakest lock that does the job:
a key-share lock on the device lets ingest and evaluation run side by side but still conflicts with quarantine.
`LockOrderIT` and the Phase 6.1 mixed-load test compare `pg_stat_database.deadlocks` before and after; in
`LockOrderIT` it was 0 before and 0 after.
