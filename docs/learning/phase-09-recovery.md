# Phase 9: Protocol C re-enrollment, split-brain traps, the backstop poller, and clock discipline

Commit: `f0e511a` (feat(recovery): protocol c re-enrollment, split-brain traps, backstop poller, clock
discipline). This is the last feature phase; after it the code is frozen.

## 1. What this phase built and why

Phase 8 ended with an incident. A laptop lid closed for about five minutes, the demo device's 4-minute leaf expired
while the machine slept, the next batch got 403 `cert_expired`, and the simulator exited 4. The only way back was a
clinician issuing a new bootstrap token (Protocol A). The certificate expiring was correct. Needing a human to recover
from it was not: the spec has a protocol for exactly this case.

Phase 9 adds four things:

- **Protocol C** (spec Section 4): a device whose leaf is gone proves its identity with its long-lived device key
  (DEK) and gets a new leaf, on the public port, with no clinician. The simulator does this on its own when its leaf
  has expired (DECISIONS 95).
- **Split-brain detection** (spec Section 2 layer 5): three traps that notice two devices using one identity, and a
  non-destructive response that revokes every certificate and asks a clinician to decide (DECISIONS 91 to 94).
- **The eviction backstop poller** (spec Section 4 "Revocation Enforcement Path"): every 3 s, revocations made outside
  the in-process path are deny-listed and their sockets closed (DECISIONS 96).
- **Clock discipline**: the Phase 8 incident also showed two clocks disagreeing by 13.6 s. Phase 9 makes every
  comparison use one clock (DECISIONS 89), measures the skew (DECISIONS 98), and lists every comparison in
  `docs/CLOCK_INVENTORY.md`.

Not built, still "Designed": CA failover to the standby Intermediate (KMS Key #3) and Redis (multi-gateway eviction
broadcast and shared rate limits).

## 2. Concept primers

### The two device keys again

A wearable holds two key pairs (spec Section 2 layer 4):

- The **OLK** (operational leaf key) signs every telemetry batch and authenticates every mTLS connection. Its
  certificate lives 12 hours (4 minutes in the demo) and is replaced by Protocol B at two thirds of that. It is used
  thousands of times a day, so it is the key most likely to leak, and it is short-lived for that reason.
- The **DEK** (device enrollment key) is created once, at Protocol A, and stored in a key partition that survives a
  state reset. The server stores its public key in `devices.dek_spki_der_b64`, anchored by a KMS Key #4 signature
  (`dek_registry_kms_sig`). It signs only two things, ever: the Protocol A enrollment proof and the Protocol C
  re-enrollment proof.

Recovery uses the DEK because the OLK is the thing that was lost. An expired, revoked or wiped OLK cannot prove
anything. The DEK is rarely used and was bound to this device by a clinician's passkey at provisioning time. That
makes it the right key for saying "I am still the device you provisioned, give me a new transport key".

### Why /challenge is stateless and rate-limited

The challenge proves freshness: the device must sign something the server issued in the last 60 seconds, so a
recorded old request cannot be replayed later. `ReEnrollChallenge` issues `{issued_at_ms, nonce, tag}`, where tag is
an HMAC over `("vitalsshield.reenroll-challenge.v1", device_id, issued_at_ms, nonce)` with a 32-byte key that exists
only in memory for this boot. Nothing is written when a challenge is issued. When it is spent, the nonce goes into
`consumed_challenge_nonces`, inside the re-enroll transaction, so it can be spent only once.

Stateless matters on this port. `/challenge` is unauthenticated: any client on the network can call it. A stored
challenge would let anyone fill a table by calling it in a loop. With a stateless one, the most such a loop can do is
burn CPU on HMACs. The rate limiter (`RateLimiter`, DECISIONS 90) caps that too: 10 per minute per remote address and
100 per minute overall, answered with 429 and Retry-After. The endpoint also never touches the database, so it cannot
be used to ask "does device X exist?".

The purpose string differs from Protocol B's (`vitalsshield.renew-challenge.v1`) and the key is separate, so a
renewal challenge never verifies as a re-enrollment one, or the other way round.

### Boot epochs: what each branch protects against

`boot_epoch` names a sequence-number space. The server assigns it and the device only ever presents the last one it
was given. The replay window is keyed by `(device_id, boot_epoch, sequence_number)`. With `s` stored and `p`
presented (`EpochRules`):

| Branch | Condition | Result | What it protects against |
|---|---|---|---|
| INVALID | p > s | 409 BOOT_EPOCH_INVALID, anomaly | A value the server never assigned. Only forged or corrupted state can hold it |
| RESYNC | clinician restore set `epoch_resync_allowed`, p <= s | assigned s + 1, sequence and bitmap reset, flag cleared | A device that lost its state partition (epoch and sequence gone). It gets a fresh sequence space instead of colliding with its own past numbers |
| REGRESSION | p < s, no resync | 409 BOOT_EPOCH_REGRESSION, anomaly | An old copy of the device state: a clone made before the last resync, or a restored backup |
| SAME | p == s | assigned s, nothing reset (DECISIONS 97) | Normal recovery from offline expiry: the device continues its sequence numbers |

### Split-brain: what a cloned key looks like from the server

Copy a wearable's flash and you have two devices with the same DEK, the same OLK, the same certificate and the same
sequence counter. Each copy works perfectly on its own. The server can only see the copies conflict. Three traps look
for that:

1. **Re-enroll collision** (DECISIONS 91): a Protocol C request while the identity is in use, meaning a usable
   certificate plus a live socket or an ingest in the last 30 s. A genuine device only re-enrolls when it has no
   usable certificate.
2. **Sequence regression** (DECISIONS 93): both copies send sequence 1, 2, 3 with different batch ids. One wins each
   number and the other gets DUPLICATE_SEQUENCE_REPLAY. Three such rejections with distinct batch ids in 60 s fire
   the trap. An idempotent retry (same batch id, same payload) is answered 200 and never counts.
3. **Post-drain** (DECISIONS 94): after a renewal, the old certificate is accepted for 60 s of grace. If it is
   presented more than 5 s after the grace ends while its successor is ACTIVE, someone still holds the old key.

### Why the response is non-destructive, and why a human decides

Every trap has a benign explanation: a device restored from a backup, a test bench running two copies, a bug. So the
anomaly response (DECISIONS 92) does only what stops further damage and keeps the evidence:

- every usable certificate is REVOKED `SUSPECTED_CLONE` (CRL reason keyCompromise) and deny-listed, and live sockets
  are closed, so neither copy can send another batch;
- `trust_state` becomes `REAUTH_REQUIRED`, so neither copy can renew or re-enroll;
- a `SECURITY_ANOMALY_ALERT` and a `SECURITY_ANOMALY` audit entry (actor `system`) record what fired and why;
- telemetry is not touched. Nothing is quarantined, no baseline is reset, no alert is retracted.

Deleting or quarantining data automatically would let an attacker who can trigger a trap erase a patient's history.
It would also make the false positive worse than the attack. A clinician looks at the alert and decides.

### Restore vs quarantine

A `REAUTH_REQUIRED` device offers two passkey step-up actions on the dashboard:

- **Restore (benign reset)**: `restore-active` (built in Phase 6) sets `trust_state = 'ACTIVE'` and
  `epoch_resync_allowed = TRUE`. The certificates stay revoked. The real device then runs Protocol C. Because
  resync is allowed, it gets epoch s + 1 and a fresh sequence space, and the permission is spent at once, so a second
  copy that tries the same is refused.
- **Quarantine (confirmed compromise)**: the existing quarantine. It clears the DEK (no Protocol C ever again),
  quarantines the lookback telemetry, resets tainted baselines and retracts alerts built on that data. The device
  must be re-provisioned through Protocol A.

### The residual risk the spec names

Spec Section 2 layer 5: if the real device powers off immediately before an attacker uses a cloned DEK to re-enroll,
the attacker's request looks exactly like an offline recovery. There is no usable certificate, no live socket and no
recent ingest, so there is no collision. The attacker gets a leaf and streams. The takeover is noticed only when the
real device comes back. Its certificate was revoked SUPERSEDED_BY_REENROLL, so it re-enrolls too. It presents the
same epoch as the attacker's, but now the attacker's certificate is in use, so the collision fires. Until then, the
attacker's batches are accepted. Only a hardware secure element that makes the DEK impossible to copy closes this.

### Clock skew, the same-clock rule, and the Docker VM sleep incident

Three clocks stamp timestamps here: the server's JVM, Postgres (inside the Docker Desktop VM), and the device. They
normally agree to milliseconds. On a Mac they do not after a sleep: the Docker VM's clock stops while the lid is
closed and catches up later. The Phase 8 soak run measured `ingested_at` (Postgres) 13.58 s behind `transmitted_at`
(host) right after the lid closed, and the expiry sweep, which compared JVM-written `not_after` with Postgres
`NOW()`, marked the expired leaf one tick late.

The same-clock rule (DECISIONS 89): compare a timestamp only with the clock that produced it. Postgres-stamped
columns (`ingested_at`, `last_ingested_at`, `issued_at`, `activated_at`, anything `DEFAULT NOW()`) are compared with
Postgres `now()`. JVM-written values (`not_before`, `not_after`, `revoked_at`, `grace_expires_at`, deny-list
`deniedFrom`, challenge `issued_at_ms`) are compared with the JVM clock. `docs/CLOCK_INVENTORY.md` lists all 30
comparisons, and 11 of them were fixed.

Changed in Phase 10b: the inventory has 31 rows (row 31, CrlService's own `Clock.systemUTC()`, was added), and 10 of
them are FIXED (row 5 in Phase 8.1, nine in Phase 9). "11" above was a miscount: ClockDisciplineIT has 10 checks of
fixed rows plus one sanity test that the JVM clock really is skewed.

`ClockSkewMonitor` (DECISIONS 98) reads `clock_timestamp()` at boot and every 60 s and subtracts the midpoint of the
JVM readings taken just before and after. The dashboard tile is amber above 2 s and red above 10 s.

### Backstop pollers as defense in depth

The in-process revocation path deny-lists, writes the row and closes sockets within milliseconds. It cannot know
about a revocation it did not make: a DBA's UPDATE, another gateway in a multi-gateway deployment (Redis pub/sub is
"Designed"), or an event lost to a crash between the commit and the eviction. The backstop poller is the slow, sure
path: every 3 s it asks the database what became REVOKED since its last poll (minus 30 s of overlap) and enforces it
again. Everything it does is idempotent, so doing it twice costs nothing.

## 3. How it works in our code

### Offline expiry recovery

```
simulator                                 public port :8444                        Postgres
   | (lid closed, leaf expired)                  |                                     |
   |-- stream: current leaf past not_after       |                                     |
   |   REJECTED cert_expired                     |                                     |
   |-- GET /challenge?device_id=X -------------->| RateLimiter, HMAC (no DB)            |
   |<-- {issued_at_ms, nonce, tag} --------------|                                     |
   |   new OLK + CSR; DEK signs                  |                                     |
   |   reEnrollProofBytes(X, t, nonce, epoch=s, sha256(csr))                           |
   |-- POST /re-enroll ------------------------->| tag, DEK anchor (Key #4), DEK sig,  |
   |                                             | CSR, new key never seen before      |
   |                                             |-- Tx 1: devices FOR UPDATE -------->|
   |                                             |   nonce, ACTIVE, assignment, horizon|
   |                                             |   epoch SAME, no collision, RESERVED|
   |                                             |-- KMS Sign (no transaction)         |
   |                                             |-- Tx 2: old certs deny-listed then  |
   |                                             |   REVOKED SUPERSEDED_BY_REENROLL,   |
   |                                             |   new cert ACTIVE, ledger RECORDED->|
   |<-- 200 {new_cert_pem, assigned_boot_epoch} -|                                     |
   |   save key, cert, epoch (atomic renames)    |                                     |
   |   RE-ENROLLED serial=... boot_epoch=s reason=cert_expired                         |
   |-- same frame, new key, mTLS :8443 --------------------------------------------->  |
```

`ReEnrollService.reEnrollBlocking` runs the checks in that order. The certificate is ACTIVE immediately: Protocol C
has no pending phase, because the device has nothing else to fall back on.

### Re-enroll collision

```
device A streaming (live socket, ingest every second)       clone B (copied keys/ and state/)
        |                                                          |
        |                                                          |-- GET /challenge, POST /re-enroll (DEK)
        |                                        Tx 1: epoch SAME; CollisionRule.fires(
        |                                              usable cert ACTIVE, not_after > JVM now,
        |                                              live socket = true, recent ingest = true)
        |                                        AnomalyService.raiseInTx(REENROLL_COLLISION):
        |                                              certs REVOKED SUSPECTED_CLONE, REAUTH_REQUIRED,
        |                                              alert, audit (last); nonce committed with it
        |<-- socket closed (after commit) ---------------------- 409 REAUTH_REQUIRED --> B exits 5
   next batch: handshake refused -> exit 3
```

### Sequence-regression trap

```
A: seq=1 batch=a1  -> 200          B: seq=1 batch=b1  -> 409 DUPLICATE_SEQUENCE_REPLAY  (hit 1)
A: seq=2 batch=a2  -> 200          B: seq=2 batch=b2  -> 409 DUPLICATE_SEQUENCE_REPLAY  (hit 2)
A: seq=3 batch=a3  -> 200          B: seq=3 batch=b3  -> 409 DUPLICATE_SEQUENCE_REPLAY  (hit 3: 3 distinct ids < 60 s)
                                          SequenceRegressionTrap fires -> AnomalyService.raiseAsync
```

`TelemetryIngestService.classifyNoRow` calls `SequenceRegressionTrap.record` only after the idempotent-retry check
has returned, so a retried frame never reaches it. Which copy loses each race does not matter: the counts are per
device.

### Post-drain trap

```
handshake (Netty event loop)                          drain (boundedElastic, every 250 ms)
DynamicMtlsTrustManager: deny-listed,                 for each queued (key, presentedAt):
  reason SUPERSEDED -> recordSupersededUse(key, now)    row RENEWED? grace + 5 s < presentedAt?
  (one queue offer, bounded, no I/O)                    ACTIVE successor? -> AnomalyService.raise
CertStatusResolver: verdict SUPERSEDED -> same          at most once per certificate
```

The handshake path only offers to a `ConcurrentLinkedQueue`. The decision needs the database, so it happens on
`boundedElastic`.

### Restore with resync

```
REAUTH_REQUIRED --(passkey step-up restore-active)--> ACTIVE, epoch_resync_allowed = TRUE, audit DEVICE_RESTORED
original: POST /re-enroll with p = 1, s = 1  -> Tx 1: RESYNC, flag consumed (FALSE)
                                             -> Tx 2: boot_epoch = 2, last_sequence_num = 0, replay_bitmap = 0
clone:    POST /re-enroll with p = 1, s = 2  -> REGRESSION (flag already spent) -> anomaly, 409, REAUTH_REQUIRED
```

The flag is consumed in Tx 1, together with the nonce. If the KMS signature or Tx 2 then fails, `voidQuietly` gives
the flag back (only if the epoch did not move), so a transient failure never turns the retry into a
BOOT_EPOCH_REGRESSION anomaly.

### Backstop poller

```
every 3 s (BackstopPoller.poll, boundedElastic):
  db_now = SELECT now()
  SELECT ... FROM certificates WHERE status = 'REVOKED' AND revoked_db_at >= (previous db_now) - 30 s
  for each: deny-list (deniedFrom = min(revoked_at, JVM now)); if a socket is live, close it
  previous db_now = db_now
```

`revoked_db_at` is new in V7. A trigger stamps it with `clock_timestamp()` whenever a row becomes REVOKED, by any
path, including a direct UPDATE.

## 4. Data model

V7 (`V7__recovery.sql`) adds to `certificates`:

| Column | Meaning |
|---|---|
| `revoked_db_at` | Set by the `certificates_revoked_db_at` trigger when status becomes REVOKED; the backstop poller's window |
| `issued_via` | `ENROLL`, `RENEW` or `REENROLL` |
| `reenroll_reason` | Protocol C only, derived by the server: `cert_expired`, `epoch_resync` or `no_usable_cert` |

Existing columns this phase relies on:

- `devices.boot_epoch`, `devices.epoch_resync_allowed`, `devices.last_sequence_num`, `devices.replay_bitmap`: the
  epoch rules read them in Tx 1, and Tx 2 writes them on a resync.
- `devices.last_ingested_at`: Postgres-stamped by the ingest CTE; the collision check compares it with `now()`.
- `consumed_challenge_nonces`: one row per spent Protocol B or C nonce, `expires_at` = issued_at_ms + 5 min (JVM).
- `clinical_alerts` with `alert_type = 'SECURITY_ANOMALY_ALERT'`: `triggering_batch_ids = '{}'`, `baseline_version`
  NULL (the lineage check requires NULL for non-drift alerts), `condition_code` one of `REENROLL_COLLISION`,
  `SEQUENCE_REGRESSION`, `POST_DRAIN_USE`, `BOOT_EPOCH_INVALID`, `BOOT_EPOCH_REGRESSION`. Because it names no
  batches, quarantine never retracts it.
- `security_audit_log` entries `SECURITY_ANOMALY` (actor `system`; payload device_id, condition_code,
  previous_state, action `REAUTH_REQUIRED` or `AUDIT_ONLY`, alert_id, certs_revoked, detail) and `DEVICE_RESTORED`
  (the clinician).
- `certificates.revocation_reason`: new values `SUSPECTED_CLONE` (CRL keyCompromise) and `SUPERSEDED_BY_REENROLL`
  (CRL superseded).

## 5. Security reasoning

What is defended:

- **A stolen expired leaf.** It cannot re-enroll: Protocol C needs the DEK, not the OLK.
- **A replayed re-enroll request.** The tag expires after 60 s, and the nonce can be spent once.
- **A forged DEK in the database.** The KMS Key #4 anchor is re-verified on every re-enrollment, so an SQL edit of
  `dek_spki_der_b64` or `provisioned_at` gives 403 DEVICE_NOT_ENROLLABLE. That is the same body as an unknown
  device, so the endpoint does not reveal which devices exist.
- **A clone streaming alongside the real device.** The sequence-regression trap catches it within seconds
  (CloneTrapIT: 775 ms with two copies at 300 ms intervals).
- **A clone re-enrolling while the real device is online.** The collision check catches it.
- **A clone holding an old leaf after a renewal.** The post-drain trap catches it.
- **A clone re-enrolling after a clinician restore.** The resync permission is spent by the first re-enrollment, and
  the clone's old epoch is a regression.
- **A revocation the process did not make.** The backstop poller enforces it within 3 s plus one poll (BackstopPollerIT:
  2468 ms).

What is not defended:

- **The offline-clone window** (spec Section 2 layer 5). A clone that re-enrolls while the real device is off looks
  like a normal recovery until the real device returns (primer above).
- **A software DEK** (spec Section 2 layer 4). Without a secure element, the DEK is a file (`keys/dek.key`, mode
  600). Anyone who can read it can re-enroll as the device until `max_renewal_horizon` expires or a clinician
  quarantines it.
- **Rate limits that only see loopback.** The limiter keys on the TCP peer address. Behind a proxy or load balancer
  every client has the proxy's address, so the per-address limit becomes a second global limit. In this demo
  everything comes from 127.0.0.1, so the per-address limit is effectively a total of 10 per minute. The limits are
  also per process: several gateways would each allow their own 100.
- **A clone that never overlaps the real device.** The traps need a conflict. Two copies taking turns (one sends
  while the other is off, each with sequence numbers above the other's) look like one device.
- **The trap thresholds are guesses.** 3 rejections in 60 s and 5 s after grace were picked for the demo. Real
  multi-gateway reordering could produce DUPLICATE_SEQUENCE_REPLAY occasionally, which is why one rejection is not
  enough.

## 6. Design decisions (DECISIONS 89 to 98)

| # | Decision | Alternative that lost |
|---|---|---|
| 89 | Same-clock rule; every comparison listed in CLOCK_INVENTORY.md | Use one clock everywhere (either all `now()` or all JVM): impossible, because Postgres stamps `DEFAULT NOW()` columns inside its own transactions and the JVM signs validity into certificates |
| 90 | Stateless HMAC challenge, separate key and purpose, in-memory token buckets | A challenge table: an unauthenticated write per GET, and a cleanup job |
| 91 | Collision only with a usable certificate in use | The spec's literal rule (certificate not revoked and ingest within 30 s), which fires on the laptop-sleep case: the leaf has just expired, the last batch was seconds ago |
| 92 | Revoke SUSPECTED_CLONE (keyCompromise), REAUTH_REQUIRED, alert, audit; telemetry untouched | certificateHold (CRL reason 6) and un-revoking on restore: un-revoking means trusting a key that was possibly copied; recovery always issues a new key instead |
| 93 | 3 rejections, distinct batch ids, 60 s | One rejection: multi-gateway reordering and duplicates would raise false alarms |
| 94 | RENEWED + 5 s after grace + ACTIVE successor; recorded in the handshake, decided off the event loop | Deciding in the trust manager: it would need JDBC on a Netty event loop |
| 95 | Simulator re-enrolls on its own after cert_expired; exit 5 for REAUTH_REQUIRED and epoch rejections; never after a revocation | Re-enrolling after any refusal: a revoked device would recover itself, defeating quarantine |
| 96 | Backstop poll on a Postgres-stamped `revoked_db_at` | Polling `revoked_at` with Postgres now(), as worded: `revoked_at` is JVM-written (or arbitrary for a direct UPDATE), so that compares two clocks (DECISIONS 89) |
| 97 | p == s keeps epoch, sequence and bitmap | Always assigning a new epoch on re-enrollment: every offline expiry would reset the replay window and break sequence continuity |
| 98 | Skew monitor, amber 2 s, red 10 s, pre-stage check | Trusting NTP: the Docker Desktop VM clock is not NTP-disciplined across a sleep |

Phase 9 deviations, also cited in the final report:

- **Backstop window column (96, 89):** the poller compares `revoked_db_at`, a Postgres-stamped column added by a V7
  trigger, not `revoked_at` as 96 is worded.
- **Resync reset timing (97, 38):** the resync's sequence and bitmap reset happens in Tx 2 together with the new
  epoch, not in Tx 1. A failed KMS signature then leaves the device unchanged. Only the resync flag is consumed in
  Tx 1, and the void path gives it back.
- **Mid-stream recovery:** the simulator resends the refused frame with the new key, so no sequence number is lost.
- **Test TTL (83):** tests use TTL PT100S, not PT80S. A PT80S leaf is due for renewal before it is issued.
- **issued_at and activated_at (89):** both are now Postgres-stamped for every protocol. Renewals used to write JVM
  times.

## 7. Verify it yourself

All outputs below are from real runs on 2026-11-18 against `bootRun` (local profile: PT4M leaves, PT60S grace,
webauthn mode) unless a test is named.

### Offline expiry (drill a)

Seed, enroll, stream, stop, wait past `not_after`, stream again:

```
./gradlew :server:seedDemoDevice --args="--device-id dev_offline_001 --patient-id patient-offline-001"
simulator factory-wipe --device-id dev_offline_001
simulator enroll --device-id dev_offline_001 --token <BOOTSTRAP_TOKEN>
ENROLLED serial=513a32298fa058dab0dfa15edcb0f022370762b1 boot_epoch=1 not_after=2026-11-18T22:39:39Z
simulator run --device-id dev_offline_001          # stopped after 126 batches; it renewed once at 22:38:19
openssl x509 -in simulator-state/dev_offline_001/state/olk.crt -noout -enddate
notAfter=Nov 18 22:41:19 2026 GMT
simulator run --device-id dev_offline_001 --count 4  # started at 22:41:24, 5 s after not_after
REJECTED cert_expired serial=2339284464079F20FBC088A97E635A84BF1558A9 not_after=2026-11-18T22:41:19Z
RE-ENROLLED serial=62E5CE88A3BA5D92CBA6E0EC206943EE727CD7F8 boot_epoch=1 reason=cert_expired at=2026-11-18T22:41:24.970385Z
SCENARIO resting
SENT seq=131 batch=cf659513 status=200 rtt_ms=30 measured_at=2026-11-18T12:46:45.781903Z scenario=resting trust_state=ACCEPTED
SENT seq=132 batch=ea12ed48 status=200 rtt_ms=17 measured_at=2026-11-18T12:47:45.781903Z scenario=resting trust_state=ACCEPTED
SENT seq=133 batch=4adcaaf9 status=200 rtt_ms=18 measured_at=2026-11-18T12:48:45.781903Z scenario=resting trust_state=ACCEPTED
```

The same epoch (1), the sequence continues from 130, no clinician, no alert. The first run lasted 2 minutes instead
of 1 (see section 9), so the leaf that expired is the one it renewed to at 22:38:19.

### Clone (drill b)

```
./gradlew :server:seedDemoDevice --args="--device-id dev_clone_001 --patient-id patient-clone-001"
simulator enroll --device-id dev_clone_001 --token <BOOTSTRAP_TOKEN>
ENROLLED serial=78e4ccd2053b13994e7880e232e53eac4c7cf96b boot_epoch=1 not_after=2026-11-18T22:44:46Z
simulator clone --device-id dev_clone_001 --to-state-dir simulator-state-clone
CLONED simulator-state/dev_clone_001 -> simulator-state-clone/dev_clone_001
simulator run --device-id dev_clone_001 &  simulator run --device-id dev_clone_001 --state-dir simulator-state-clone &
```

Last lines of each (both exit 3):

```
original:
SENT seq=2 batch=688e696b status=409 rtt_ms=7 measured_at=2026-11-18T10:42:47.336799Z scenario=resting error=DUPLICATE_SEQUENCE_REPLAY
SENT seq=3 batch=24ead575 status=409 rtt_ms=11 measured_at=2026-11-18T10:43:47.336799Z scenario=resting error=DUPLICATE_SEQUENCE_REPLAY
REJECTED handshake_refused last_ok_seq=0 ms_since_last_ok=3242
clone:
SENT seq=2 batch=b5c83d99 status=200 rtt_ms=10 measured_at=2026-11-18T10:42:47.336176Z scenario=resting trust_state=ACCEPTED
SENT seq=3 batch=7e62d555 status=200 rtt_ms=13 measured_at=2026-11-18T10:43:47.336176Z scenario=resting trust_state=ACCEPTED
REJECTED handshake_refused last_ok_seq=3 ms_since_last_ok=1021
```

The copy that started a few milliseconds later won every race this time. Which copy wins does not matter: the trap
counts rejections per device.

```
   device_id   |   trust_state   | boot_epoch | last_sequence_num | epoch_resync_allowed
 dev_clone_001 | REAUTH_REQUIRED |          1 |                 3 | f

   device_id   |       alert_type       |   condition_code    | alert_status | triggering_batch_ids | baseline_version
 dev_clone_001 | SECURITY_ANOMALY_ALERT | SEQUENCE_REGRESSION | ACTIVE       | {}                   |

    serial    | status  | revocation_reason | issued_via
 78e4ccd2053b | REVOKED | SUSPECTED_CLONE   | ENROLL

   device_id   | trust_state | count
 dev_clone_001 | ACCEPTED    |     3

     event_type     |      actor_id      |        code         | revoked
 ASSIGNMENT_CREATED | dev-seed-clinician |                     |
 DEVICE_PROVISIONED | dev-seed-clinician |                     |
 SECURITY_ANOMALY   | system             | SEQUENCE_REGRESSION | 1
```

To recover after a Touch ID restore on the dashboard: `simulator re-enroll --device-id dev_clone_001` resyncs the
original to epoch 2. The same command with `--state-dir simulator-state-clone` then prints
`REAUTH_REQUIRED code=BOOT_EPOCH_REGRESSION` and exits 5. The headless run below did exactly that.

### Headless Chrome (virtual authenticator, isolated server on ports 9443 to 9445)

```
clockTile = CLOCK SKEW (DB VS SERVER) -1 ms GREEN checked 5:35:15 PM
expiredHint = CERT_EXPIRED_NO_SUCCESSOR Device must re-enroll (Protocol C) or be re-provisioned
renewalLogRow = dev_cdp9_exp RE-ENROLLED via DEK cert_expired 2D1F33CC091055EB… 5:35:46 PM 5:35:46 PM –
exits = [3, 3]
reauthButtons = ['Restore (benign reset)', 'Quarantine (confirmed compromise)']   side by side: True
firstAlertRow = PINNED 5:35:50 PM dev_cdp9_clone SECURITY SEQUENCE_REGRESSION 3 batches with distinct batch ids ...
stateAfterRestore = ACTIVE resync=true
originalReEnroll = RE-ENROLLED serial=2F81B2C25BF3A9890A4814B8D51DACF763CBBCD5 boot_epoch=2 reason=manual previous_boot_epoch=1
cloneReEnroll = EXIT 5 / REAUTH_REQUIRED code=BOOT_EPOCH_REGRESSION
console = []   exceptions = []
```

### Tests

```
OfflineExpiryRecoveryE2E:
OFFLINE_TIMELINE enrolled serial=4E94CDC1DBB0E5A5F9757928245FB43001284A8E not_after=2026-11-18T22:24:42Z at=2026-11-18T22:24:02.241315Z
OFFLINE_TIMELINE streamed seq=1..10 until=2026-11-18T22:24:05.268219Z
OFFLINE_TIMELINE woke at=2026-11-18T22:24:43.004358Z (1004 ms after not_after)
OFFLINE_TIMELINE REJECTED cert_expired serial=4E94CDC1DBB0E5A5F9757928245FB43001284A8E not_after=2026-11-18T22:24:42Z
OFFLINE_TIMELINE RE-ENROLLED serial=201E5F759C7FADB9C9EF2D033C64238E08362A4B boot_epoch=1 reason=cert_expired at=2026-11-18T22:24:43.075511Z
OFFLINE_TIMELINE SENT seq=11 batch=24f2b842 status=200 rtt_ms=11 ...
OFFLINE_TIMELINE SENT seq=20 batch=c2202ca1 status=200 rtt_ms=11 ...
OFFLINE_TIMELINE quarantine certs_revoked=1 batches_quarantined=25 exit=3

CloneTrapIT:   CLONE_TRAP tripped_ms=775 exit_original=3 exit_clone=3
               CLONE_REENROLL Reauth[status=409, code=BOOT_EPOCH_REGRESSION]
BackstopPollerIT:   BACKSTOP_EVICTION_MS=2468
                    Backstop poller closed 1 live socket(s) of revoked certificate 3da0093c20667d71c09817e48635bb09f1aa3c9a
```

## 8. How the tests prove it

| Test | Property |
|---|---|
| `ChallengeTagTest` (4) | the tag binds device_id and every field; 60 s vs 60.001 s in both directions; another boot key and the renewal purpose do not verify |
| `RateLimiterTest` (3) | 10 per address then 429 with Retry-After 6 s; 100 global across addresses; a refused request takes no token |
| `EpochRulesTest` (4) | every branch, including resync with p < s and p == s, and p > s even with resync |
| `CollisionRuleTest` (6) | usable + socket fires; usable + recent ingest fires; expired + recent ingest does not (laptop sleep); revoked does not; RENEWED past grace does not |
| `SequenceRegressionTrapTest` (6) | 2 in 60 s no, 3 yes; idempotent retries ignored; other codes ignored; the window slides; per device; disabled |
| `PostDrainTrapTest` (5) | within grace no; grace + 4 s no; exactly 5 s no; grace + 6 s with successor yes; no successor no |
| `ClockSkewMonitorTest` (3) | 0, 1999, 2001, 10001 ms map to GREEN, GREEN, AMBER, RED; Postgres behind counts the same; a failed query is UNKNOWN |
| `SimulatorStateStoreTest` (+2) | re-enrollment keeps sequence and measured_at, replaces key and epoch, drops pending; clone copies both partitions with permissions |
| `ReEnrollIT` (10) | offline expiry with p == s: same epoch, seq 4 to 6 accepted, old cert REVOKED SUPERSEDED_BY_REENROLL, ledger invariant; mid-stream 403 OUTSIDE_VALIDITY recovers and resends the same frame; tampered anchor and unknown device give the same 403 body; wrong DEK signature 400; REAUTH_REQUIRED 403 then nonce replay 409; challenge for another device 401; horizon 409; CSR with an old key 400; p > s and p < s raise the anomaly with telemetry untouched; restore then resync to s + 1 with sequence and bitmap reset |
| `CollisionIT` (2) | a clone re-enrolling while the device streams: 409 REAUTH_REQUIRED, REENROLL_COLLISION, both sockets evicted, every cert SUSPECTED_CLONE, telemetry still ACCEPTED, one audit entry; expired cert + ingest 5 s ago re-enrolls with no anomaly |
| `CloneTrapIT` | two copies streaming: REAUTH_REQUIRED in under 10 s by SEQUENCE_REGRESSION, both exit 3, telemetry unchanged; restore; original resyncs to epoch 2 and streams; clone gets BOOT_EPOCH_REGRESSION and REAUTH_REQUIRED again |
| `PostDrainTrapIT` | old cert within grace is accepted with no anomaly; at grace + 6 s the handshake is refused and POST_DRAIN_USE fires; the successor is revoked too |
| `BackstopPollerIT` | a direct SQL revocation (revoked_at = 2020) closes the live socket within 4 s and the handshake is refused |
| `ClockDisciplineIT` (11) | with the JVM 10 min behind Postgres, each FIXED row of CLOCK_INVENTORY.md uses the right clock |
| `OfflineExpiryRecoveryE2E` | stream, sleep past not_after, resume: RE-ENROLLED with no clinician action, same epoch, seq 11 to 20 all 200, quarantine still ends it with exit 3 |

## 9. Gotchas hit during this phase

- **PT80S is due for renewal before it is issued.** Leaves are backdated 60 s, and renewal is due at 2/3 of the
  validity from `notBefore`. A PT80S leaf is due 53 s after `notBefore`, which is 7 s before issuance, so the
  simulator would renew before every batch. Every Phase 9 test that waits for an expiry uses PT100S (lives about
  40 s, due about 7 s after issuance).
- **The traps tripped old tests that misbehave on purpose.** ConcurrentDuplicateIT and ReplayWindowPropertyIT send
  many distinct batches with reused sequence numbers to test the window CTE. That is a clone to the
  sequence-regression trap: the device was revoked mid-test (`EOFException: connection closed before a response`).
  RenewalE2E presents every old leaf long after its grace to prove the handshake refuses it, which is a post-drain
  event. Those three classes switch the relevant trap off with a property and a comment pointing to the test that
  covers it.
- **An exact assertion across two clocks.** RenewalIT asserted `grace_expires_at - activated_at == 3 s` and failed
  with `3.002719S`. After DECISIONS 89, `activated_at` is Postgres `now()` and `grace_expires_at` is JVM time. The
  assertion is now a range.
- **Two JVM clocks.** `PkiConfig` built `CertificateProfiles` with `Clock.systemUTC()` while everything else used the
  `Clock` bean. ClockDisciplineIT, with the bean 10 minutes behind, then got `PKIX validation failed: validity check
  failed` for a freshly issued leaf. Certificate validity is now written with the bean too.
- **A test directory that did not exist.** `cat > signer/BackstopPollerIT.java` failed with `no such file or
  directory` inside a long heredoc chain, and the next command ran anyway. Only the "no tests found" output showed it.
- **SIGINT to a background job.** The drill's "Ctrl-C after a minute" used `kill -INT` on a job started with `&` in
  a non-interactive shell, where SIGINT is ignored. The simulator streamed for 2 minutes and renewed once before it
  was stopped with SIGTERM.
- **The anomaly did not show in the revocation log.** The first headless run showed "No revocations since boot" right
  after a SUSPECTED_CLONE revocation: only SignerRevocationService fed that list. AnomalyService and ReEnrollService
  now record their revocations there too.
- **A Java map in a clinician-facing sentence.** The explanation read `({DUPLICATE_SEQUENCE_REPLAY=3})`; it is now
  `(3 DUPLICATE_SEQUENCE_REPLAY)`, and explanations end with a full stop.

## 10. Judge Q&A

**Q: What happens if someone copies the device's keys?**
A: It depends on when they use them. If the copy streams while the real device does, both send the same sequence
numbers; within three rejected batches (under a second in CloneTrapIT) the sequence-regression trap revokes every
certificate, sets REAUTH_REQUIRED and raises a security alert. If the copy tries to re-enroll while the real device
is online, the collision check does the same. If it holds an old leaf after a renewal, the post-drain trap does. If
the copy re-enrolls while the real device is off, it gets in. It stays in until the real device returns and
collides. That is the residual risk the spec names; only a hardware secure element for the DEK removes it.

**Q: Why don't you delete the data when you detect a clone?**
A: Because every trap has innocent explanations and the data belongs to a patient. The anomaly response stops both
copies at once (revoked certificates, closed sockets, REAUTH_REQUIRED), keeps every batch, and asks a clinician. If
it was a compromise, the clinician quarantines, which marks the lookback window QUARANTINED, resets tainted baselines
and retracts the alerts built on them. That is reversible review, not deletion. Deleting automatically would hand an
attacker a way to erase a patient's history by triggering a trap.

**Q: Your laptop went to sleep and the cert expired. Then what?**
A: Now it recovers by itself. On wake, the next batch is refused as expired (or the simulator sees its leaf is past
not_after at launch). It asks for a challenge, signs it with its DEK together with its stored boot_epoch, and gets a
new leaf. The leaf is not a collision because the old one is expired, however recent the last batch was. Then it
resends the refused frame with the new key and carries on with the same epoch and sequence numbers.
OfflineExpiryRecoveryE2E does exactly this; the manual drill below shows the RE-ENROLLED line. No clinician is
involved and no alert is raised.

**Q: Why is the re-enroll endpoint on the public port with no client certificate?**
A: The device has no certificate that works; that is why it is re-enrolling. Its identity proof is the DEK signature
over a fresh server challenge, checked against a public key that a KMS-held key anchored at provisioning. The TLS
connection only gives confidentiality and authenticates the server.

**Q: Couldn't an attacker lock a patient's device out by triggering a trap?**
A: Only by holding the device's keys (to send accepted-looking batches or a valid DEK proof) or by being on the
mTLS port with its certificate, which also needs its key. Anyone who has the keys can do worse. Without the keys,
/challenge and /re-enroll requests fail the signature check before any state changes, and challenge requests are rate
limited.

**Q: Why do you care which clock a timestamp came from?**
A: Because they drift apart in exactly the situation demos happen in: a laptop that slept. In the Phase 8 soak run
Postgres was 13.6 s behind the JVM, and a sweep that compared a JVM time with Postgres NOW() was a tick late. The rule
now is that every comparison uses the clock that wrote the value. The inventory lists all 31 places, and
ClockDisciplineIT runs the server 10 minutes off to prove the 10 fixed ones (counts corrected in Phase 10b).
