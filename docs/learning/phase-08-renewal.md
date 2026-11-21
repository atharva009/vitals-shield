# Phase 8: Protocol B renewal with first-use switchover, grace drain, and demo TTL rollover

Commit: `e732bfc` (feat(renewal): protocol b with first-use activation, grace drain, and demo ttl rollover).

## 1. What this phase built and why

A device leaf used to live 12 hours, and the only way to get a new one was Protocol A again: a clinician approves a
fresh bootstrap token with a passkey. That is right for provisioning and wrong for routine key rotation. Phase 8 adds
Protocol B (spec Section 4): a device that holds a valid ACTIVE leaf proves it still holds that leaf's key (the OLK),
proves it holds a new key (a CSR), and receives a new leaf without any human step.

The new leaf does not take over at once. It is stored `ISSUED_PENDING_USE` and becomes ACTIVE only when the first
telemetry batch signed by it is accepted (first-use switchover). The old leaf then becomes RENEWED and keeps working
for a bounded grace window (60 s by default), after which it is refused at the handshake and its live sockets are
closed by a scheduled eviction.

The local/demo profile shortens the leaf to `PT4M`, so a rollover is visible on the dashboard every 1m40s.

Phase 7 follow-ups also landed here: an evaluation queue cap with counters (DECISIONS #79), wider SD floors
(DECISIONS #72), a deterministic in-flight retraction test, and a headless-browser run of the Phase 7 panels (two UI
fixes, section 9).

Not built: Protocol C (re-enrollment after a lost key) and split-brain detection (two devices using one identity).

## 2. Concept primers

### Short-lived certificates as a complement to revocation

Revocation is only as fast as the slowest party that checks it. Our gateway checks per request and evicts live sockets
in milliseconds, but a CRL copy cached somewhere else is only as fresh as its nextUpdate. A short validity bounds the
damage no matter who is checking: a stolen leaf that nobody revokes still stops working at `not_after`. The two work
together: revocation is fast when someone notices, expiry is certain when nobody does.

### Why renew at 2/3 of validity

Renewing at the last moment leaves no room for failure: one lost response or a KMS outage and the device expires.
Renewing very early wastes signatures and shortens the effective benefit of short lifetimes. Two thirds leaves the
final third (4 h of a 12 h leaf, 80 s of a 4 min one) for retries. The rule is `not_before + 2/3 x (not_after -
not_before)` (DECISIONS #83), in `RenewalDueRule` (simulator) and `AdminOverviewService.renewalDueAt` (dashboard).

Our leaves are backdated: `notBefore = issuance - 60 s` (clock skew tolerance, CertificateProfiles). So a PT4M leaf
lives 3 minutes after issuance and is due 2m40s after notBefore, which is 1m40s after issuance:

```
notBefore          issued            due (2/3)                  notAfter
   |-------60 s-------|-------100 s-------|--------80 s---------|
   0                 60                 160                    240  seconds
```

### The full lifecycle

```
                Protocol A                          Protocol B (renew)
                    |                                      |
                    v                                      v
                 ACTIVE  <---- first accepted batch ---- ISSUED_PENDING_USE
                    |                                      |
   successor's      |                                      | another renewal before use
   first batch      v                                      v
                 RENEWED (grace_expires_at)             REVOKED (REPLACED_BEFORE_USE)
                    |
     grace passes   v
             "superseded": deny-listed, sockets closed, row stays RENEWED until not_after

   Any live state --quarantine/re-enroll--> REVOKED       Any live state --past not_after (sweeper)--> EXPIRED
```

### First-use activation and the flaky-link problem it solves

If the server switched to the new leaf when it sent the renew response, a response lost on a flaky link would leave
the device holding only the old leaf, which the server has already retired: the device is locked out. With first-use
activation the server changes nothing about the old leaf until the new leaf has proved, by signing an accepted batch,
that the device actually has it. Until then both work.

### The grace window and why it is bounded and enforced

After the switchover, requests already in flight on the old leaf's connection, or a retry of a frame signed before the
switch, should not fail. A grace window (60 s, `vitalsshield.pki.renewal-grace`) covers that. It is bounded so an
attacker holding the old key cannot keep using it, and it is enforced three ways: the deny-list entry for the old key
has `deniedFrom = grace_expires_at` (handshake), the per-request status check reads `grace_expires_at` from the row,
and GraceEviction closes the old key's live sockets at that instant (DECISIONS #84).

### Stateless HMAC challenges vs stored challenges

A stored challenge means a DB write per GET and a table to clean. Ours is stateless: the server returns `issued_at_ms`,
a 16-byte nonce, and `tag = HMAC-SHA256(bootKey, purpose || issuer_key_hash || serial || issued_at_ms || nonce)`. When
the renew request comes back, recomputing the tag proves this boot issued it for that certificate at that time. The
key is 32 random bytes made at boot and never stored, so a restart invalidates every outstanding challenge, and the GET
writes nothing (DECISIONS #81).

### Nonce consumption and replay

A valid tag can be presented twice. Inside renewal Tx 1 the nonce is inserted into `consumed_challenge_nonces`; a
primary-key conflict is 409 CHALLENGE_REPLAYED. The row expires 5 minutes after issued_at and a sweeper deletes it
every 5 minutes. Deleting is safe because a challenge older than 60 s fails the tag check anyway.

### Why the renewal body must match the TLS cert

The body names `issuer_key_hash` and `serial_number`, and the OLK proof signs them. If the server took them from the
body alone, a device holding certificate A on its connection could ask to renew certificate B. Check 1 requires the
body to equal the connection's certificate (else 403 RENEWAL_CERT_MISMATCH), and the HMAC tag is bound to the same
serial, so a challenge fetched by one device cannot be spent by another.

### Proof of the old key (OLK proof) vs proof of the new key (CSR)

Two different statements. The `olk_renewal_sig` is the current OLK signing encoding 5 (issuer, serial, issued_at,
nonce, sha256(CSR)): "the holder of the current leaf's key asks for this exact CSR, now". The CSR's self-signature
says "whoever made this CSR holds the new private key". Without the first, anyone could request a leaf for their own
key; without the second, a device could be issued a leaf for a key it does not hold. The server also refuses a new
key equal to the current OLK or to the DEK (400 PROOF_INVALID), so the DEK stays a provisioning-only key.

### REPLACED_BEFORE_USE and why unused certs still go on the CRL

When a renew response is lost the device renews again, and the first new leaf is never used. It was still signed by
the CA and exists somewhere (in the response that was lost, perhaps in a proxy log). Everything the CA signs must be
either current or revoked, so the server revokes it with reason REPLACED_BEFORE_USE, which maps to CRL reason
`superseded`, and deny-lists it before the commit.

### max_renewal_horizon as a periodic authorization check

Renewal needs no human, so something must stop a device from renewing forever. Every assignment has a
`max_renewal_horizon`; past it, Tx 1 answers 409 RENEWAL_HORIZON_EXCEEDED and the device needs a new assignment
(a clinician action). Short leaves plus a horizon turn "authorized once" into "authorized until a date".

## 3. How it works in our code

### Challenge, renew, pending

```
device (current OLK on TLS)                    server (mTLS port)
  GET /api/v1/devices/renew-challenge  ----->  CertStatusResolver: cert row ok
                                       <-----  {issued_at_ms, nonce, tag}      (no DB write)
  new OLK, CSR; sig = OLK(encoding 5)
  POST /api/v1/devices/renew           ----->  1 body == TLS cert            else 403 RENEWAL_CERT_MISMATCH
                                               2 tag valid, |age| <= 60 s     else 401 CHALLENGE_INVALID
                                               3 cert ACTIVE, now < not_after else 409 CERT_NOT_RENEWABLE
                                               4 sig verifies (current key)  else 400 PROOF_INVALID
                                               5 CSR valid, key != OLK, DEK  else 400 PROOF_INVALID
                                               Tx 1: devices FOR UPDATE (ACTIVE else 403), nonce INSERT
                                                     (409 CHALLENGE_REPLAYED), assignment and horizon (409s),
                                                     serial RESERVED
                                               KMS Sign (no transaction)
                                               Tx 2: devices FOR UPDATE, presenting cert FOR UPDATE (still
                                                     ACTIVE), serial RECORDED, old pending: deny-list then
                                                     REVOKED REPLACED_BEFORE_USE, INSERT new ISSUED_PENDING_USE
                                               after commit: evict + CRL if a pending was revoked
  persist olk-pending.key/.crt (600)   <-----  200 {new_cert_pem, current_assignment_id, assignment_active_from}
```

`RenewalService` holds this; KMS is never called inside a transaction. A KMS or DB failure is 503 with a Retry-After
of 3 to 8 s and the serial is VOIDED (and, if a leaf was signed, stored REVOKED and deny-listed).

### First batch, activation, grace, eviction

```
simulator: new HttpClient with the pending cert; next batch signed by it
   POST /api/v1/telemetry/ingest ---> resolver: ISSUED_PENDING_USE accepted; JWS verified; CTE inserts row
                                 <--- 200 (response is not delayed)
   promote pending -> current (rename), print ACTIVATED
server, on boundedElastic, then this batch's clinical evaluation is queued:
   CertificateActivationService.activate (one transaction)
     devices FOR UPDATE -> new cert FOR UPDATE (still pending? else return)
     grace = now + 60 s; deny-list(old, deniedFrom = grace)         <- before commit
     UPDATE old: ACTIVE -> RENEWED, grace_expires_at                <- first, so the unique index holds
     UPDATE new: ISSUED_PENDING_USE -> ACTIVE, activated_at
   after commit: Mono.delay(grace - now) -> evictByCert(old)       (GraceEviction)
```

Five batches arriving at once each call `activate`; the device row lock runs them one at a time and only the first
finds the row still pending (ActivationConcurrencyIT).

### Lost response, second renewal

```
renew #1: server stores P1 (pending)   response lost; device still on OLD, renewal still due
renew #2: Tx 2 finds P1 pending: deny-list P1, P1 REVOKED REPLACED_BEFORE_USE; stores P2 (pending)
P1 on the CRL (reason superseded), P1 handshake refused; P2 activates on its first batch
```

### ASSIGNMENT_CHANGED, renewal

```
batch N  (old assignment id)  -> 409 ASSIGNMENT_CHANGED {current_assignment_id}
simulator: store the new id, renew now (DECISIONS #86) -> 200 {current_assignment_id = new}
batch N+1 (new id, new cert)  -> 200 -> activation
```

### Quarantine during renewal

`SignerRevocationService.revokeAllForDevice` now locks the device row and the certificate rows FOR UPDATE inside its
transaction, deny-lists every key it found, then revokes `ACTIVE`, `ISSUED_PENDING_USE` and `RENEWED` together. A renewal
Tx 2 or an activation either commits before it (and its certificate is revoked too) or runs after it and finds the
presenting certificate no longer ACTIVE (renewal aborts and voids) or the pending one no longer pending (activation
does nothing).

### Sweepers

`RenewalSweepers`, started at LISTENERS_BOUND, on its own one-thread scheduler:
- every 30 s, expired certificates: live rows past `not_after` become EXPIRED, deny-listed from `not_after` before commit,
  sockets evicted;
- every 30 s, stale reservations: RESERVED serials older than 2 minutes (crash after Sign) become VOIDED, deny-listed,
  CRL republished;
- every 5 minutes, consumed nonces past `expires_at` are deleted.

Changed in Phase 8.1: the expiry sweep runs one transaction per certificate (devices FOR UPDATE, then certificates FOR
UPDATE), compares `not_after` with the server clock instead of Postgres `NOW()`, logs the previous status, and also runs
once at boot inside DENY_LIST_SEEDED. See section 11.

### Simulator

```
state/olk.key, olk.crt                    current
state/olk-pending.key, olk-pending.crt    renewed, before its first 200 (mode 600, atomic rename)
```

On launch a valid pending pair is preferred. Before each batch: if not using a pending leaf and the current one is
due, renew over the current leaf. A failed renewal prints `RENEW_FAILED status=... error=CODE` and streaming continues
on the current leaf (retry after 5 s or Retry-After). If the current leaf expires anyway, the next handshake fails and
the simulator prints `REJECTED cert_expired` and exits 4. The frame retry rules (DECISIONS #44) did not change.

## 4. Data model

`certificates` lifecycle columns:

| column | meaning |
|---|---|
| `status` | ISSUED_PENDING_USE, ACTIVE, RENEWED, REVOKED, EXPIRED; partial unique indexes allow one ACTIVE and one pending per device |
| `superseded_serial` | set on a Protocol B leaf: the serial it replaces |
| `grace_expires_at` | set on the old leaf at switchover: activated_at + renewal-grace |
| `issued_at` (V6) | when the CA signed it |
| `activated_at` (V6) | when its first batch switched it to ACTIVE |
| `revocation_reason` | now also REPLACED_BEFORE_USE for an unused renewal |

`consumed_challenge_nonces` (from V1, first used now): `nonce_b64` primary key, `device_id`, `expires_at` (issued_at +
5 min), index on `expires_at` (V6).

`issued_serials` for renewals: RESERVED in Tx 1, RECORDED in Tx 2, VOIDED on abort, KMS failure, or the 30 s sweep. The
DECISIONS #38 invariant (no certificate row without a RECORDED ledger row) is asserted after every RenewalIT case.

`telemetry_records.issuer_key_hash/serial_number` record the leaf that signed each batch, so after a rollover the rows
show which leaf carried what.

Lock order (DECISIONS #82): devices -> certificates -> telemetry_records -> patient_device_assignments -> clinical_alerts
-> audit advisory lock last. Every transaction-opening class states its part at the top of the file.

## 5. Security reasoning

What renewal adds:
- **Bounded key exposure.** An OLK is useful for at most one leaf lifetime plus grace. A key copied today is useless
  tomorrow unless the thief also renews, which needs the key before the real device rotates it.
- **Periodic authorization.** Every renewal re-checks device state (ACTIVE), the assignment, and `max_renewal_horizon`.
  A quarantined or unassigned device cannot renew.
- **Every signed serial is accounted for.** Reserved before Sign, recorded or voided after; unused leaves are revoked
  and listed. A crash after Sign is cleaned by the sweep (RenewalIT.crashAfterSignIsVoidedBySweepAndListed).
- **Fail closed.** Deny-list adds happen before the DB commit in renewal Tx 2, activation, quarantine, and both sweeps.

What it does NOT defend against:
- **A cloned key renewing first.** If an attacker copies the current OLK and renews before the real device, the
  attacker gets the new leaf and the real device's next renewal fails with 409 CERT_NOT_RENEWABLE or its old leaf is
  superseded after grace. Detecting that (two holders of one identity) is split-brain detection and recovery is
  Protocol C, both out of scope. What we do give: the real device's failures are visible (RENEW_FAILED, 403s) and a
  quarantine revokes every leaf of the device.
- **Renewal while KMS is down.** Signing needs KMS. Tx 1 has already reserved a serial, Sign fails, the serial is VOIDED
  and the device gets 503 with Retry-After. The device keeps streaming on its current leaf; with a 12 h leaf renewed at
  8 h there are 4 hours of outage tolerance, with the PT4M demo leaf 80 seconds. The spec's degraded-mode table covers
  the wider policy.

## 6. Design decisions (DECISIONS #81 to #86)

| # | Decision | Alternatives that lost |
|---|---|---|
| 81 | Body serial must equal the TLS cert; HMAC tag over purpose, issuer, serial, issued_at, nonce; key random per boot | Trust the body (lets one device renew another's serial); stored challenges (a DB write per GET, a cleanup job, no gain) |
| 82 | Lock order gains certificates, after devices | Lock certificates first (renewal and activation already hold the device row; certificates-first deadlocks against them) |
| 83 | Renew at 2/3 of validity everywhere; demo TTL PT4M | Fixed "renew N minutes before expiry" (does not scale between 4 min and 12 h); PT40S demo leaf (born expired with the 60 s backdate) |
| 84 | GraceEviction closes old sockets at grace_expires_at; sweeper marks EXPIRED | Rely on the per-request check only (an idle keep-alive socket stays open until its next request) |
| 85 | Simulator persists pending before use, promotes after first 200, prefers a valid pending on restart | Overwrite current on 200 from /renew (a crash between the write and the first batch loses the only working key) |
| 86 | Renew immediately on 409 ASSIGNMENT_CHANGED | Wait for the 2/3 point (the leaf would keep carrying the previous assignment's authorization for hours) |

Also: #78 (stale clinical streaks restart), #79 (evaluation queue cap), #80 (manual Touch ID record).

## 7. Verify it yourself

Against `bootRun` with the local profile (TTL PT4M, grace PT60S), on 2026-11-17 UTC:

```
$ ./gradlew -q :server:seedDemoDevice --args="--device-id dev_renew_001"
BOOTSTRAP_TOKEN=zPOt...DWAE                       (shortened here)
$ simulator/build/install/simulator/bin/simulator factory-wipe --device-id dev_renew_001
FACTORY_WIPED simulator-state/dev_renew_001
$ simulator/build/install/simulator/bin/simulator enroll --device-id dev_renew_001 --token <token>
ENROLLED serial=3990583ee7bd27f0fb16db59f5ee29ce8761b95a boot_epoch=1 not_after=2026-11-17T00:00:46Z
$ simulator/build/install/simulator/bin/simulator run --device-id dev_renew_001 --scenario resting
SCENARIO resting
SENT seq=1 batch=4538a369 status=200 rtt_ms=132 measured_at=2026-11-16T11:57:55.300576Z scenario=resting trust_state=ACCEPTED
...
RENEWED old=3990583EE7BD27F0FB16DB59F5EE29CE8761B95A new=1C4AE60317EADA31CD0A68CD0BFD3A5CC1A9A27F due_at=2026-11-16T23:59:26Z at=2026-11-16T23:59:26.931396Z
ACTIVATED new=1C4AE60317EADA31CD0A68CD0BFD3A5CC1A9A27F at=2026-11-16T23:59:26.978202Z
RENEWED old=1C4AE60317EADA31CD0A68CD0BFD3A5CC1A9A27F new=5454B0E6D43D052A6023FA1DB66F7DAB8021B849 due_at=2026-11-17T00:01:06Z at=2026-11-17T00:01:06.396844Z
ACTIVATED new=5454B0E6D43D052A6023FA1DB66F7DAB8021B849 at=2026-11-17T00:01:06.422094Z
RENEWED old=5454B0E6D43D052A6023FA1DB66F7DAB8021B849 new=4919C83BFB5C6BDF48E7B45FC7E98781B0806F87 due_at=2026-11-17T00:02:46Z at=2026-11-17T00:02:47.061383Z
ACTIVATED new=4919C83BFB5C6BDF48E7B45FC7E98781B0806F87 at=2026-11-17T00:02:47.082074Z
RENEWED old=4919C83BFB5C6BDF48E7B45FC7E98781B0806F87 new=5CF0F4637EC15A25A19454CAC0DF30696CC70DB7 due_at=2026-11-17T00:04:27Z at=2026-11-17T00:04:27.516875Z
ACTIVATED new=5CF0F4637EC15A25A19454CAC0DF30696CC70DB7 at=2026-11-17T00:04:27.544429Z
RENEWED old=5CF0F4637EC15A25A19454CAC0DF30696CC70DB7 new=100E403A77DB0F452B908C392BA782E2BB5DCAC7 due_at=2026-11-17T00:06:07Z at=2026-11-17T00:06:07.938977Z
ACTIVATED new=100E403A77DB0F452B908C392BA782E2BB5DCAC7 at=2026-11-17T00:06:07.966776Z
```

504 batches, every one 200. Rollovers are 1m40s apart, and ACTIVATED follows RENEWED by 22 to 50 ms (the very next
batch). The certificate rows at 00:06:31:

```
$ docker compose exec -T postgres psql -U vitalsshield -d vitalsshield -c "select status, left(serial_number,12), superseded_serial is not null as renewed_from, grace_expires_at, not_after from certificates where device_id='dev_renew_001' order by not_before"
 status  |     left     | renewed_from |       grace_expires_at        |       not_after
---------+--------------+--------------+-------------------------------+------------------------
 EXPIRED | 3990583ee7bd | f            | 2026-11-17 00:00:26.977636+00 | 2026-11-17 00:00:46+00
 EXPIRED | 1c4ae60317ea | t            | 2026-11-17 00:02:06.421452+00 | 2026-11-17 00:02:26+00
 EXPIRED | 5454b0e6d43d | t            | 2026-11-17 00:03:47.082474+00 | 2026-11-17 00:04:06+00
 EXPIRED | 4919c83bfb5c | t            | 2026-11-17 00:05:27.543277+00 | 2026-11-17 00:05:47+00
 RENEWED | 5cf0f4637ec1 | t            | 2026-11-17 00:07:07.966191+00 | 2026-11-17 00:07:27+00
 ACTIVE  | 100e403a77db | t            |                               | 2026-11-17 00:09:07+00
```

Read it top to bottom: the enrolled leaf (renewed_from f) and four renewed ones. Each `grace_expires_at` is 60 s after
the next leaf's activation, and 20 s before the leaf's own `not_after`. Superseded leaves stay RENEWED until the 30 s
sweeper sees them past `not_after` and marks them EXPIRED. An earlier query, at 00:02:47, caught `1c4ae60317ea` still
RENEWED 21 s after its `not_after`: the sweep had not run yet, and the handshake and the per-request validity check
refuse an expired leaf anyway.

RenewalE2E (TTL PT2M, grace PT3S, one batch per second for 75 s) reported:

```
RENEWED old=16E09BC46D4DA5AA75ABC2EA4F053AA791D0A6C1 new=194BA2FDEC4BD710FE61550D7388DB9D617A4C05 due_at=2026-11-17T00:07:25Z at=2026-11-17T00:07:25.733244Z
ACTIVATED new=194BA2FDEC4BD710FE61550D7388DB9D617A4C05 at=2026-11-17T00:07:25.752366Z
RENEWED old=194BA2FDEC4BD710FE61550D7388DB9D617A4C05 new=27CAB0EBA92FBC1B0A0ADC3F7CC122EF22C8F596 due_at=2026-11-17T00:07:45Z at=2026-11-17T00:07:45.273560Z
ACTIVATED new=27CAB0EBA92FBC1B0A0ADC3F7CC122EF22C8F596 at=2026-11-17T00:07:45.288856Z
RENEWED old=27CAB0EBA92FBC1B0A0ADC3F7CC122EF22C8F596 new=5E35EFE365271A6D71F83C443745DF9EA7668ECD due_at=2026-11-17T00:08:05Z at=2026-11-17T00:08:05.749408Z
ACTIVATED new=5E35EFE365271A6D71F83C443745DF9EA7668ECD at=2026-11-17T00:08:05.770662Z
REJECTED handshake_refused last_ok_seq=74 ms_since_last_ok=1013
ROLLOVER_TIMINGS
  serial=16E09BC4... status=EXPIRED issued=00:07:05.185Z since_prev_issue=-       issue_to_activation_ms=-  grace_expires=00:07:28.753Z
  serial=194BA2FD... status=RENEWED issued=00:07:25.724Z since_prev_issue=20539ms issue_to_activation_ms=28 grace_expires=00:07:48.288Z
  serial=27CAB0EB... status=RENEWED issued=00:07:45.268Z since_prev_issue=19543ms issue_to_activation_ms=19 grace_expires=00:08:08.770Z
  serial=5E35EFE3... status=ACTIVE  issued=00:08:05.744Z since_prev_issue=20475ms issue_to_activation_ms=26 grace_expires=-
ROLLOVERS renewed=3 activated=3 batches=74 non200=0 old_certs_refused_after_grace=3 quarantine_revoked=3 exit=3
```

The headless-Chrome run of the Phase 7 arc (0e) on an isolated server (fresh Postgres on 5434, ports 9443 to 9445):

```
"signedInWithPasskey": true,
"enroll": "ENROLLED serial=6cef2608ebfb9a947be357848f642f091ef3b212 boot_epoch=1 not_after=2026-11-17T00:01:02Z",
"simScenarioLines": ["SCENARIO resting", "SCENARIO drift", "SCENARIO acute"], "simNon200": [],
"baselineBefore": "Baseline LOCKED v1 HR ref 66.4 ± 3.1 bpm HRV ref 49.9 ± 5.0 ms SpO2 ref 97.9 ± 1.00 % ...",
"alertsBefore": ["... ACUTE RESTING_HR_HIGH Resting heart rate 150 bpm for 5+ min (limit 140) ... ACTIVE",
                 "... DRIFT Drift vs baseline v1: HR z=+5.4, HRV z=-3.8, SpO2 z=-2.3 over 4 resting batches 4 v1 ACTIVE"],
"result": "8.8 ms revocation latency · 1 cert(s) revoked · 0 socket(s) closed · 23 batches quarantined · 1 baselines reset · 2 alerts retracted approved by dr_cdp8 (passkey step-up)",
"baselineAfter": "Baseline CALIBRATING v2 Calibration 0 / 10 resting batches ...",
"alertsAfter": both RETRACTED_BY_QUARANTINE, opacity 0.5, text-decoration line-through,
"console": [], "exceptions": []
```

HR SD 3.1 and HRV SD 5.0 show the new floors at work (the HRV SD is the floor itself). With Phase 7's floors the same
script gave HR z=+9.3.

## 8. How the tests prove it

| Property | Test |
|---|---|
| Tag valid; issued_at, nonce, serial, issuer, tag tampering rejected; 60 s accepted, 60.001 s rejected (both directions); other boot key rejected; MessageDigest.isEqual | RenewalChallengeTest |
| 2/3 boundary for 12 h and PT4M with the 60 s backdate | RenewalDueRuleTest |
| Encoding 5 signs and verifies end to end; every field bound | RenewalProofTest (crypto-common) |
| Pending saved 600, promoted, discarded on re-enroll; interrupted promotion finished on load | SimulatorStateStoreTest |
| Renew -> pending, both certs ping; first batch activates; old RENEWED with grace = activated_at + 3 s; old pings 200 in grace; after grace the kept-alive socket is closed by GraceEviction and the handshake is refused | RenewalIT.happyPathPendingActivationGraceAndEviction |
| The per-request check refuses a RENEWED cert once the stored grace has passed (403 SUPERSEDED) | RenewalIT.perRequestCheckRefusesRenewedCertOnceTheStoredGraceHasPassed |
| Lost response: first pending REVOKED REPLACED_BEFORE_USE, on the CRL as superseded, handshake refused; one pending; second activates | RenewalIT.lostResponseRenewTwiceBeforeUse |
| 409 CHALLENGE_REPLAYED, 401 for 61 s old, 401 for another serial's tag, 403 RENEWAL_CERT_MISMATCH | RenewalIT.challengeAndBindingRejections |
| Pending cert to /renew: 409 CERT_NOT_RENEWABLE | RenewalIT.pendingCertCannotRenew |
| Wrong signing key, CSR = OLK, CSR = DEK, broken CSR: 400 PROOF_INVALID; nothing issued | RenewalIT.proofRejections |
| QUARANTINED 403, closed assignment 409 DEVICE_UNASSIGNED, past horizon 409 RENEWAL_HORIZON_EXCEEDED; no serial reserved | RenewalIT.deviceAndAssignmentRejections |
| Crash after Sign: VOIDED by the sweep, on the CRL | RenewalIT.crashAfterSignIsVoidedBySweepAndListed |
| Ledger invariant after every case | RenewalIT @AfterEach |
| 5 parallel first batches: one switchover, no failures, RENEWED + ACTIVE, 5 rows | ActivationConcurrencyIT |
| Quarantine with RENEWED, ACTIVE, pending: all REVOKED KEY_COMPROMISE, sockets closed, all on the CRL, handshakes refused | QuarantineDuringRenewalIT |
| 409 ASSIGNMENT_CHANGED -> renew -> new assignment and new cert; exactly one non-200 | AssignmentChangedRenewalIT |
| Past not_after -> EXPIRED, deny-listed, handshake refused | ExpiredSweeperIT |
| Quarantine waits behind a paused evaluation, then retracts its alert | InFlightRetractionIT |
| Queue capacity 2: third batch 200, unevaluated, counted | ClinicalQueueCapIT |
| About 75 s of streaming: rollovers, zero non-200, old certs refused after grace, quarantine exits 3 | RenewalE2E |

## 9. Gotchas hit during this phase

- **The new sweepers starved the shared scheduler in the full suite.** ConcurrentDuplicateIT failed twice with
  `SocketTimeoutException: Read timed out`, only in the full run, as in Phase 7. Cached Spring contexts whose Postgres
  container had stopped kept running the 30 s sweeps on the shared boundedElastic pool, each waiting up to 30 s for a
  connection. `RenewalSweepers` now has its own one-thread scheduler; the next full run passed 189 of 189.
- **A PT40S test leaf is born expired.** notBefore is backdated 60 s, so `notAfter = issuance - 20 s`. RenewalE2E uses
  PT2M (60 s of life, renewal 20 s after issuance) instead.
- **PT4M broke two Phase 3 assumptions.** EnrollmentIT asserted a 12 h validity, and the simulator treated a stored leaf
  as enrolled only with 5 minutes left (a PT4M leaf never has that), so a restart re-enrolled.
  `Simulator.MIN_REMAINING_VALIDITY` is now 30 s, because `run` renews before expiry.
- **Quarantine revokes before it flips the device state.** `QuarantineService` calls `revokeAllForDevice` first and
  sets QUARANTINED afterwards. So renewal Tx 2 rechecks that the presenting certificate is still ACTIVE (not only that
  the device is), and `revokeAllForDevice` now locks the device and certificate rows so nothing is inserted between its
  SELECT and UPDATE.
- **The 403 after grace cannot be seen over the wire.** At `grace_expires_at` the handshake deny-list entry starts and
  GraceEviction closes the sockets, so no old-cert connection survives to receive a 403. RenewalIT shows the
  per-request layer separately by moving `grace_expires_at` back in the DB while the in-memory entry still has the
  original instant.
- **Two UI bugs found by the headless run (0e).** The alert Condition cell broke codes mid-word ("RESTING_HR_H / IGH")
  because `.mono` uses `word-break: break-all`; it now wraps only at code boundaries. After a quarantine, the device
  card's thumbprint and validity still described the revoked certificate under "none ACTIVE"; it now shows "Last
  certificate ... REVOKED" first.

## 10. Judge Q&A

**Q: Why short-lived certs if you already have CRLs and live eviction?**
A: Revocation needs someone to notice. Eviction and per-request checks make our own gateway react in milliseconds, but
only after a clinician quarantines. A key copied without anyone noticing keeps working until its leaf expires, so the
lifetime is the upper bound on unnoticed misuse. With renewal at 2/3, a 12 h leaf bounds that to hours instead of the
years a typical device certificate has, at the cost of one KMS signature per device per 8 hours.

**Q: What happens if the renewal response is lost on a flaky link?**
A: Nothing breaks. The server stored the new leaf as ISSUED_PENDING_USE and left the old one ACTIVE. The device never
saw the new leaf, keeps streaming on the old one, finds renewal still due, and renews again. That second renewal
revokes the unused leaf as REPLACED_BEFORE_USE (on the CRL as superseded) and stores a new pending one. RenewalIT runs
exactly this.

**Q: The device switches to the new cert before the server knows it got it. What if that first batch fails?**
A: The switch on the server happens only on an accepted batch. If the first batch fails (network error), the simulator
retries the same frame on the new connection; the pending leaf is accepted for requests, so the retry can succeed. If
the process crashes, the pending pair is on disk and is preferred on restart. The old leaf stays ACTIVE throughout.

**Q: Can an attacker with a stolen old certificate use the grace window?**
A: Only during the 60 s after the real device's first batch on the new leaf, and only for requests the gateway would
accept from the old leaf anyway (it is the same key). After that the handshake is refused, open sockets are closed,
and the per-request check reads `grace_expires_at`. A stolen key is a quarantine case: quarantine revokes the RENEWED,
ACTIVE and pending leaves together with no grace.

**Q: What happens if a device is offline past its certificate's expiry?**
A: It is locked out until someone re-provisions it. The leaf's notAfter has passed, so the handshake fails certificate
validation, and a request on a socket that was already open gets 403 `cert_expired` from the per-request check. Within
30 s the expiry sweep deny-lists the leaf from `not_after`, marks it EXPIRED and closes its live sockets; if the server
was down at the time, the boot sweep does this before the listeners bind. The simulator prints `REJECTED cert_expired`
and exits 4. It cannot renew, because renewal requires a valid current leaf. The overview flags the device
`CERT_EXPIRED_NO_SUCCESSOR`, and today the fix is a new bootstrap token and a fresh enrollment. Phase 9 adds automatic
re-enrollment with the device key (Protocol C).

**Q: Why HMAC challenges instead of a challenge table?**
A: A table makes every GET a write and needs cleanup, and it proves nothing more: the HMAC tag already proves the
server issued the challenge, for which certificate, and when. The one thing a tag cannot stop is reuse, so the nonce is
written once, when it is spent, inside the renewal transaction. A restart drops the HMAC key, which invalidates every
outstanding challenge without any cleanup.

## 11. Changed in Phase 8.1

### The soak run as evidence

After the Phase 8 commit, `dev_renew_001` streamed against `bootRun` with the local profile (PT4M leaves, PT60S grace)
until the laptop lid closed. The numbers below come from the database, with this query:

```sql
SELECT count(*) AS batches_accepted,
       min(ingested_at) AS first_ingested, max(ingested_at) AS last_ingested,
       max(ingested_at) - min(ingested_at) AS span,
       count(DISTINCT serial_number) AS certs_used,
       max(sequence_number) AS last_seq
  FROM telemetry_records WHERE device_id = 'dev_renew_001';

SELECT count(*) AS renewals,
       min(activated_at - issued_at) AS min_issue_to_activation,
       max(activated_at - issued_at) AS max_issue_to_activation,
       percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM activated_at - issued_at) * 1000)
           AS median_ms
  FROM certificates WHERE device_id = 'dev_renew_001' AND superseded_serial IS NOT NULL;

SELECT min(gap) AS min_gap, max(gap) AS max_gap, avg(gap) AS avg_gap
  FROM (SELECT issued_at - lag(issued_at) OVER (ORDER BY issued_at) AS gap
          FROM certificates WHERE device_id = 'dev_renew_001') g WHERE gap IS NOT NULL;
```

```
 batches_accepted |        first_ingested         |         last_ingested         |      span       | certs_used | last_seq
------------------+-------------------------------+-------------------------------+-----------------+------------+----------
             7787 | 2026-11-16 23:57:55.450106+00 | 2026-11-17 02:10:39.702642+00 | 02:12:44.252536 |         80 |     7787

 renewals | min_issue_to_activation | max_issue_to_activation | median_ms
----------+-------------------------+-------------------------+-----------
       79 | 00:00:00.018328         | 00:00:00.052463         |    33.066

     min_gap     |     max_gap     |     avg_gap
-----------------+-----------------+-----------------
 00:01:39.101682 | 00:01:40.669233 | 00:01:40.046833
```

7,787 batches were accepted over 2 h 12 min 44 s. That is every batch the simulator sent before the sleep: its log shows
`SENT seq=1` to `seq=7787` with `status=200`. The 7,787 batches used 80 certificates, linked by 79 renewals issued 1 min
39.1 s to 1 min 40.7 s apart (the 2/3 rule on a 3-minute life). Issuance to activation took 18 to 52 ms, with a median
of 33 ms. `last_ingested` is earlier than the last batch's `measured_at` (02:10:53.28) because of the clock skew
described below.

### What happened at sleep

The macOS power log shows `Entering Sleep state due to 'Clamshell Sleep'` at 21:10:18 EST (02:10:18Z), short dark wakes,
and then sleep from 21:10:52 to 21:15:38. The current leaf `7BDA31EE…` had been activated at 02:09:30.64 with
`not_after` 02:12:30, so it expired with no successor while the machine slept. Renewal would have been due at 02:10:50,
which fell inside the sleep. After wake, the simulator's next batch was refused by the per-request check:

```
SENT seq=7788 batch=0ce40838 status=403 rtt_ms=14 measured_at=2026-11-17T02:11:53.280218Z scenario=resting
REJECTED cert_expired serial=7BDA31EE19F6EA0B1022CA60C721708878CC2EC
```

and it exited 4, as designed: an expired leaf cannot renew itself.

Changed in Phase 9: exit 4 is now rare. On cert_expired the simulator re-enrolls with its DEK (Protocol C,
DECISIONS 95) and keeps streaming with the same boot_epoch and sequence numbers; exit 4 remains only when Protocol C
itself cannot run (for example no DEK). See phase-09-recovery.md.

### The sweep fix

The Phase 8 sweep already selected ACTIVE, ISSUED_PENDING_USE and RENEWED rows. What looked like a gap was a clock
skew. The server log shows that the first sweep after wake expired only the older leaf:

```
21:15:51.990 RenewalSweepers : Certificate 7accdce9dc50… of dev_renew_001 EXPIRED (not_after 2026-11-17T02:10:50Z)
21:15:52.574 HikariPool : Thread starvation or clock leap detected (housekeeper delta=5m27s457ms).
21:16:21.982 RenewalSweepers : Certificate 7bda31eee19f… of dev_renew_001 EXPIRED (not_after 2026-11-17T02:12:30Z)
```

The sweep compared `not_after <= NOW()`, and `NOW()` is the clock of the Docker VM that runs Postgres. That clock
stops while the Mac sleeps and catches up afterwards. Here is `ingested_at` (Postgres `NOW()`) minus `transmitted_at`
(the simulator, host clock) for the last batches before the sleep:

```
 sequence_number |        transmitted_at         |          ingested_at          | skew_s
            7778 | 2026-11-17 02:10:30.568937+00 | 2026-11-17 02:10:30.575533+00 |   0.01
            7779 | 2026-11-17 02:10:45.165357+00 | 2026-11-17 02:10:31.589458+00 | -13.58
            7787 | 2026-11-17 02:10:53.281063+00 | 2026-11-17 02:10:39.702642+00 | -13.58
```

The VM lost 13.6 s in a 16 s dark-wake cycle. After the 286 s sleep it was further behind, so for one tick `NOW()` was
before 02:12:30 while the server clock was 02:15:51. The handshake and the per-request check read the JVM clock (the
host clock), so they refused the leaf correctly. Only the stored status was late, by one tick.

Phase 8.1 changes (DECISIONS 87):
- the sweep compares `not_after` with `clock.instant()` from the server, the same clock as the handshake and the
  per-request check;
- each certificate gets its own transaction: devices FOR UPDATE, then the certificate FOR UPDATE, re-checked;
  deny-listed from `not_after` before commit; EXPIRED; sockets evicted after commit (lock order DECISIONS 82);
- one INFO line per certificate, with the OpenSSL serial and the previous status, for example
  `Certificate 7608AD635108DF0D38A18941AE5F10CD53893381 of dev_active_exp EXPIRED (was ACTIVE, not_after
  2026-11-18T21:02:43Z)`;
- the sweep also runs inside the DENY_LIST_SEEDED boot step, before LISTENERS_BOUND;
- the overview sets `needs_attention: "CERT_EXPIRED_NO_SUCCESSOR"` when the newest certificate is EXPIRED and there is
  no ACTIVE or pending one. The dashboard shows it as an amber chip with "Device must re-enroll (Protocol C) or be
  re-provisioned".

`ExpiredSweeperIT` now starts its context by hand (leaf TTL PT80S, which lives about 20 s, since PT20S would be born
expired under the 60 s backdate) and stops the periodic sweep, so every sweep in the test is an explicit call:

| Test | Proves |
|---|---|
| `sweepDoesNotTouchValidCerts` | a valid ACTIVE leaf is not swept, not deny-listed, still answers 200 |
| `pendingCertExpiresUnused` | an ISSUED_PENDING_USE leaf past `not_after` becomes EXPIRED; the ACTIVE one stays |
| `renewedCertExpires` | a RENEWED leaf past `not_after` becomes EXPIRED; its successor stays ACTIVE |
| `certPastNotAfterBecomesExpiredAndDenied` | the Phase 8 case: deny-list entry with reason EXPIRED, handshake refused |
| `activeCertExpiresWithoutSuccessor` | a real X.509 expiry: after not_after the socket is still open and the row ACTIVE; one sweep makes it EXPIRED and closes the socket with nothing sent on it; the handshake is refused; the overview shows EXPIRED and CERT_EXPIRED_NO_SUCCESSOR |
| `expiredWhileServerDown` | `not_after` set in the past while the context is closed; on restart the row is ACTIVE at TRUST_ANCHORS_LOADED and EXPIRED at DENY_LIST_SEEDED and LISTENERS_BOUND |

### Why measured_at did not jump

The rejected batch says `measured_at=02:11:53.28`, exactly 60 s after the previous batch, although about 5 minutes of
wall-clock time had passed. The compressed clock is `min(max(last + 60 s, now - 12 h), now)` (DECISIONS 74). After
about 12 minutes of streaming it catches up with now and is capped there, so during the soak batches were stamped about
1 s apart. After the stall the cap no longer applied, and the step was the plain `last + 60 s`. A wall-clock stall
therefore shows in `measured_at` as one 60 s step, never as its real length. It shows in `ingested_at`, which is why
quarantine selects on `ingested_at` OR `measured_at` (DECISIONS 88). This is intended: `measured_at` is clinical time,
and the gap was not measured.


### The ConcurrentDuplicateIT timeouts, again

The first full `./gradlew integrationTest` of Phase 8.1 failed two ConcurrentDuplicateIT tests with
`java.net.SocketTimeoutException: Read timed out`, the same symptom as in Phase 7 and Phase 8. Run on its own, the
class passed. The console showed why: 49 `expired-cert sweep failed: ... CannotGetJdbcConnectionException` warnings
from 28 sweep threads, plus `HikariPool-44 - Failed to validate connection ... (This connection has been closed.)` on
`boundedElastic` threads. Spring caches every test context, and each integration class has its own Postgres
container, so a finished class leaves a live context pointed at a stopped database. Its periodic jobs (deny-list
refresh, KMS health, CRL watch) then each hold a shared `boundedElastic` thread for Hikari's 30 s connection timeout,
and live ingest work waits behind them. Phase 8 moved only the sweeper to its own scheduler.

The fix is in `server/build.gradle`: `spring.test.context.cache.maxSize=1` for every test task. No context is ever
reused by another class here (each has its own container and ports), so the cache only ever held dead contexts. With
the cap, a context is closed as soon as the next class starts its own. The rerun passed 194 of 194 tests with no
dead-context warnings, in 2 min 7 s instead of 3 min 21 s.
