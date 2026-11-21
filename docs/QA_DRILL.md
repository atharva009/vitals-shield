# Judge questions drill

Short answers for the Q&A after the demo. Each answer matches the code as built (Phase 10a.1). "D" numbers are rows
of `docs/DECISIONS.md`. Evidence names a test (fully qualified) and/or a command to show.

Test tiers: untagged tests run in `./gradlew test`, `@Tag("integration")` in `./gradlew integrationTest`,
`@Tag("e2e")` in `./gradlew e2eTest`. In the commands below, `psql` means
`docker compose exec -T postgres psql -U vitalsshield -d vitalsshield`, and `$CRL` means
`curl -s --cacert var/trust/root-ca.pem https://127.0.0.1:8444/api/v1/pki/intermediate-crl.pem`.

## Top 10

### ★ 1. Is every certificate your CA signed accounted for?

Every device leaf, yes (D38). Its serial is reserved in `issued_serials` as RESERVED in the same short transaction that
claims the token, before any KMS call; activation marks it RECORDED, an aborted activation marks it VOIDED (and stores
the signed leaf as REVOKED, REPLACED_BEFORE_USE), and a sweep at boot voids RESERVED serials older than 2 minutes.
VOIDED serials go on the CRL as superseded, so even a leaf we lost is revocable. The exception is the gateway's own TLS
leaf from the Server TLS CA: not in the ledger and that CA publishes no CRL (D39); it lives 24 h and its key never
leaves memory.

Evidence: `com.vitalsshield.server.pki.SerialReservationIT.everyCertificateHasLedgerRow`,
`com.vitalsshield.server.pki.SerialReservationIT.reclaimRaceLoserIsVoidedAndOnCrl`,
`com.vitalsshield.server.pki.SerialReservationIT.crashAfterSignIsVoidedByBootSweep`,
`com.vitalsshield.server.renewal.RenewalIT.crashAfterSignIsVoidedBySweepAndListed` (all use the
`LedgerInvariant` helper, which runs `IssuedSerialLedger.INVARIANT_SQL`). Live:
`psql -c "SELECT count(*) FROM certificates c LEFT JOIN issued_serials s USING (issuer_key_hash, serial_number) WHERE s.serial_number IS NULL OR s.status = 'RESERVED'"`
returns 0.

### ★ 2. What happens if someone copies a device's keys?

Three traps catch a copy that overlaps the real device, and each one runs the same anomaly response (D92): every
usable certificate is revoked as SUSPECTED_CLONE, sockets are closed, the device goes to REAUTH_REQUIRED, a security
alert and an audit entry are written, and no telemetry is changed. The traps are: two copies streaming (3 sequence
rejections with distinct batch ids in 60 s, D93; 775 ms in CloneTrapIT, about 1 s on stage), a re-enroll while the
real device is online (collision, D91), and an old leaf used more than 5 s after its grace (post-drain, D94). Not
caught: a copy that re-enrolls while the real device is off looks like a normal recovery until the real device comes
back, and a copy taken just before a scheduled renewal can win the renewal race and run alone (D102). The fix for the
first is a secure element for the device key; the fix for the second is a designed, not built, trap.

Evidence: `com.vitalsshield.server.anomaly.CloneTrapIT.twoCopiesStreamingTripTheTrapThenRestoreLetsOnlyTheOriginalBack`,
`com.vitalsshield.server.reenroll.CollisionIT.clonedDekReEnrollingWhileTheDeviceStreamsIsReauthRequired`,
`com.vitalsshield.server.anomaly.PostDrainTrapIT.oldCertificateWithinGraceIsFineAfterGracePlusSixIsAnAnomaly`,
`com.vitalsshield.server.e2e.NormalOperationNoAnomalyE2E.normalDeviceBehaviorRaisesNoAnomaly` (no false positives).
Stage: `scripts/stage/05-clone.sh dev_stage_002`.

### ★ 3. What stops someone with database access from enrolling a rogue device?

Signatures they cannot make without KMS Key #4 or a clinician's passkey. A token row only enrolls if its stored
WebAuthn assertion verifies over the recomputed ProvisioningDigest (origin, RP id hash, UP and UV) under a passkey
whose row carries a Key #4 signature (D56, D57). The device key (DEK) row is also anchored by a Key #4 signature, so a
swapped DEK fails at enrollment and at every re-enrollment. A forged token gets 403 PROVISIONING_UNVERIFIED and causes
no KMS Sign call; a compromised server process or Key #4 credentials would defeat this.

Evidence: `com.vitalsshield.server.admin.webauthn.ProvisioningReverifyIT.sqlForgedTokenIsRefusedWithoutAnyKmsSign`,
`com.vitalsshield.server.admin.webauthn.PasskeyAnchorIT.swappedPublicKeyFailsWithAnAnchorErrorAndUntouchedRowsVerify`,
`com.vitalsshield.server.enrollment.EnrollmentIT.dekAnchorDetectsTamper`,
`com.vitalsshield.server.reenroll.ReEnrollIT.tamperedAnchorAndUnknownDeviceAreTheSame403`.

### ★ 4. Why short-lived certs if you have CRLs?

Revocation only helps once someone notices. A key copied without anyone noticing works until its leaf expires, so the
lifetime is the upper bound on unnoticed misuse: 12 h in production, renewed at 8 h (2/3 of validity, D83). Every
renewal also re-checks device state, the assignment, and `max_renewal_horizon`, so authorization is re-decided
periodically. The cost is one KMS signature per device every 8 hours.

Evidence: `com.vitalsshield.simulator.RenewalDueRuleTest.twelveHourLeafRenewsAtEightHours`,
`com.vitalsshield.server.renewal.RenewalIT.deviceAndAssignmentRejections`,
`com.vitalsshield.server.e2e.RenewalE2E.streamsThroughRolloversThenQuarantineEndsIt`.

### ★ 5. Why LocalStack and not real KMS, and what changes in production?

LocalStack lets the demo run with no AWS dependency, and it has the same API and cryptography (ECC_NIST_P256,
ECDSA_SHA_256, DER output), but none of the custody: the keys are data in a container, with no HSM and no IAM. In
production the endpoint override goes away and the code stays the same; what changes is real HSM custody, IAM roles,
and the split the spec describes (gateway with zero KMS permissions, separate signer service, separate DB roles,
offline Root ceremony), none of which is built today. Also, only the local profile may rebuild a lost hierarchy; any
other profile refuses to start before it creates a key.

Evidence: `com.vitalsshield.server.pki.ReconciliationIT.prodProfileFailsClosed`,
`com.vitalsshield.server.kms.KmsSmokeIT.signatureIsDer`. Spec Section 8 table.

### ★ 6. What does the revocation latency number measure?

From when the quarantine service starts (after the Touch ID assertion has been verified) to when every close future
of the device's sockets has completed (D11). In between: deny-list every live certificate, mark them REVOKED in one
transaction, close every channel. It excludes the browser round trip, the sanitize step after it, and CRL
republication, which starts after eviction; in the timed rehearsal it was 8,674 microseconds, and the e2e test requires under 500 ms
on each of 5 runs.

Evidence: `com.vitalsshield.server.e2e.SpineE2E.spineFiveTimes` (prints `revocation_latency_micros`),
`com.vitalsshield.server.gateway.MtlsListenerIT.revokeClosesLiveKeepAliveSocket`. Dashboard quarantine result shows
`revocation_latency_micros`.

### ★ 7. Are the clinical thresholds validated?

No. The z-score limits, the calibration window, the SD floors and the acute limits are engineering defaults (spec
Section 6), all configurable under `vitalsshield.clinical.*` so a clinical team could set them. What the project shows
is that every alert is traceable to signed batches and a baseline version, and is withdrawn when that evidence is
quarantined.

Evidence: `com.vitalsshield.server.clinical.ClinicalPropertiesTest.boundDefaultsEqualDefaults`,
`com.vitalsshield.server.clinical.QuarantineRetractionIT.quarantineRetractsExactlyTheTaintedAlerts`.

### ★ 8. How do you sign a certificate if the CA key never leaves KMS?

BouncyCastle builds the to-be-signed bytes, we hash them with SHA-256 locally and call KMS Sign with MessageType
DIGEST (D17), and KMS returns a DER ECDSA signature that goes straight into the certificate or CRL. Each result is
verified against the issuer's public key before use. The JVM only ever holds key ARNs; the one private key outside KMS
is the gateway's own TLS key, generated in memory at each boot (D15).

Evidence: `com.vitalsshield.server.kms.KmsSignerIT.signsSha256DigestAndVerifiesWithJca`,
`com.vitalsshield.server.pki.PkiOpensslIT.crlsVerify`, `com.vitalsshield.server.boot.BootSequenceIT.noPrivateKeyOnDisk`.
Live: `psql -c "SELECT purpose, status FROM kms_keys WHERE status = 'ACTIVE'"` shows the four keys.

### ★ 9. What stops a captured batch from being replayed?

A 64-bit sliding window on (device, boot_epoch, sequence_number), updated in the same SQL statement as the insert.
Each sequence is accepted once; anything more than 63 behind the newest is rejected; an identical re-send (same batch
id and payload) gets 200 as an idempotent retry without a second row. The boot epoch is assigned by the server, so a
wiped device cannot reopen old sequence space.

Evidence: `com.vitalsshield.server.telemetry.ReplayWindowPropertyIT.endpointMatchesModel` (2000 random operations
against a model), `com.vitalsshield.server.telemetry.ConcurrentDuplicateIT.twentyIdenticalFramesStoreOneRow`,
`com.vitalsshield.server.telemetry.ConcurrentDuplicateIT.sameSequenceDifferentBatchesAcceptsOne`.

### ★ 10. What would you build next?

First, the trap D102 calls for: refuse and flag a renewal attempted from a certificate whose successor was issued to
a different key, which closes the renewal race. Then the production split (gateway with no KMS rights, separate
signer service, per-service DB roles), a secure element for the device key, and a standby Intermediate (Key #3) for
failover. After that: Redis for multi-gateway eviction and shared rate limits, S3 Object Lock anchoring of the audit
chain, a durable clinical evaluation outbox (D79), and TLS on the admin plane.

Evidence: D102, D79, D8, D62; `docs/demo-fallback.md` section 9 ("Designed, not built").

## PKI and certificates

### How are your serials generated?

`SerialAllocator` draws 20 bytes from the JDK `SecureRandom` and `SerialNumbers.random` clears the top bit and
rejects zero. That gives a positive DER INTEGER of at most 20 octets (the RFC 5280 limit) with 159 random bits, well
above the 64 bits the CA/Browser Forum requires for public TLS. Serials are never sequential, so they leak nothing
about volume and cannot be predicted (the 2008 MD5 rogue-CA attack relied on predictable serials).

Evidence: `com.vitalsshield.server.pki.SerialAllocatorTest` (10,000 draws: SecureRandom source, positive, at most 20
octets, unique, not monotonic, top bit 158, each bit set in 40% to 60%).

### How do you stop a device certificate being used as a server certificate, or to make a sub-CA?

Devices chain to the Device Intermediate with critical EKU clientAuth; the gateway chains to a separate Server TLS CA
with serverAuth (D2). Leaves are critical CA:FALSE and both intermediates have pathlen:0. The trust manager also
rejects a CA:TRUE or non-clientAuth leaf on its own.

Evidence: `com.vitalsshield.server.pki.PkiOpensslIT.deviceLeafVerifiesForClientAuthOnly`,
`com.vitalsshield.server.pki.PkiOpensslIT.gatewayLeafVerifiesForServerAuthOnly`,
`com.vitalsshield.server.pki.trust.DynamicMtlsTrustManagerTest.caTrueLeafFails`.

### Is the CRL how you revoke devices?

No. The CRL is the signed public record for outside relying parties; our gateway enforces revocation through the
handshake deny-list, a post-handshake gate, a per-request DB check, and socket eviction. CRLs are cached, republished
in the background after each revocation and before nextUpdate, and a GET never signs (D27). Reasons map to RFC 5280
codes: quarantine and suspected clone are keyCompromise, replaced or re-enrolled are superseded.

Evidence: `com.vitalsshield.server.gateway.MtlsListenerIT.crlRepublishedOnRevoke`,
`com.vitalsshield.server.gateway.MtlsListenerIT.crlGetsDoNotSign`,
`com.vitalsshield.server.pki.PkiOpensslIT.revokedLeafAppearsOnIntermediateCrl`. Live: `$CRL | openssl crl -noout -text`.

## KMS and key custody

### What happens if a KMS key disappears?

At runtime, the health monitor (DescribeKey every 30 s) turns UNHEALTHY and shows a red banner, but never rebuilds
(D49); a network error shows as UNKNOWN, not as a lost key. At the next boot, the local profile rebuilds all four keys
and the hierarchy, revokes every leaf as HIERARCHY_REBUILD and sends devices back to provisioning (D12); every other
profile refuses to start.

Evidence: `com.vitalsshield.server.admin.KmsHealthMonitorTest.networkErrorIsUnknownNotMissing`,
`com.vitalsshield.server.admin.AdminOverviewIT.kmsKeyLossIsReported`,
`com.vitalsshield.server.pki.ReconciliationIT.pendingDeletionKeyTriggersFullRebuild`,
`com.vitalsshield.server.pki.ReconciliationIT.prodProfileFailsClosed`.

### What happens if KMS is down during enrollment or renewal?

The device gets 503 with Retry-After and nothing is lost. For enrollment the token goes back to ISSUED (D34); for
renewal the reserved serial is VOIDED and the device keeps streaming on its current leaf. With a 12 h leaf renewed at
8 h that is 4 hours of outage tolerance.

Evidence: `com.vitalsshield.server.enrollment.EnrollmentIT.kmsFailureReturnsToken`.

### Are the gateway and the signer separate services?

No. Gateway, admin plane and CA signer run in one Spring Boot process and connect to Postgres as one role. An attacker
running code in that process can call KMS Sign while they are there. The spec's split (gateway with zero KMS
permissions, separate signer, separate DB roles) is designed, not built.

Evidence: spec Section 8 table; `docs/learning/phase-01-pki-core.md` section 5.

## mTLS and revocation

### Why alert 46 and not 44?

Because that is what JSSE sends. We attach a CertPathValidatorException with reason REVOKED (and keep EXPIRED for
validity failures) so a provider could send 44 or 45 (D37). But in JDK 21, `CertificateMessage.checkClientCerts` (the
server checking a client, TLS 1.2 and 1.3) always sends `CERTIFICATE_UNKNOWN`, alert 46; the cause-to-alert mapping
only runs when a client checks a server. So a revoked device cannot tell "revoked" from "unknown", which also tells
an attacker less.

Evidence: `com.vitalsshield.server.pki.trust.DynamicMtlsTrustManagerTest.denyListedLeafFails` (cause is REVOKED).
Live: `sleep 1 | openssl s_client -connect 127.0.0.1:8443 -cert revoked.pem -key revoked.key -CAfile var/trust/root-ca.pem 2>&1 | grep -i alert`
prints `SSL alert number 46`.

### TLS resumption skips certificate checks. How does a revoked device not resume?

We make resumption impossible: after the handshake check the server invalidates the session (D26). The JDK still
sends a NewSessionTicket, but presenting it gets a full handshake ("New", never "Reused"), so the trust manager runs
again and the client proves key possession again.

Evidence: `com.vitalsshield.server.gateway.ResumptionIT.resumedSessionNeverReaches200AfterRevoke`.

### What if a certificate is revoked by direct SQL, outside your process?

The next request on any connection is refused, because the per-request check reads the database. A backstop poller
(every 3 s, D96) also deny-lists it and closes its live sockets; a V7 trigger stamps `revoked_db_at` so a fake
`revoked_at` cannot hide it. Measured: 2,468 ms from the SQL update to the socket closing.

Evidence: `com.vitalsshield.server.signer.BackstopPollerIT.directSqlRevocationClosesTheLiveSocketWithinFourSeconds`,
`com.vitalsshield.server.e2e.TelemetryPerRequest403E2E.ingestOnSameConnectionAfterRevokeIs403`.

## JWS and replay

### Your JWS could carry its own key. How do you stop that?

The header may contain only `alg` (must be ES256), `typ` (must be vitalsshield.telemetry+jws) and `x5t#S256`; `jwk`,
`jku`, `x5c`, `x5u` and `crit` are rejected (D43). The verification key always comes from the TLS client certificate
of that connection, and `x5t#S256` must match both that certificate and the stored thumbprint.

Evidence: `com.vitalsshield.crypto.JwsPolicyTest.forbiddenHeaderParametersRejected`,
`com.vitalsshield.crypto.JwsPolicyTest.otherAlgorithmsRejected`,
`com.vitalsshield.server.telemetry.TelemetryIngestIT.x5tOfAnotherCertIsCertMismatch`,
`com.vitalsshield.server.telemetry.TelemetryIngestIT.differentKeyWithCorrectX5tIsSigInvalid`.

### Does a valid signature mean the vitals are real?

No. It proves origin and integrity: this device's key signed this batch and it has not changed. A rooted device can
sign false values; plausibility bounds catch impossible ones, and quarantine removes what a compromised window
produced. We store the JWS so any batch can be re-verified offline later.

Evidence: `com.vitalsshield.server.telemetry.TelemetryIngestIT.storedJwsReverifiesOfflineAgainstStoredCert`,
`com.vitalsshield.server.telemetry.TelemetryIngestIT.implausibleHrIsStoredAndConsumesItsSequence`.

## Enrollment, renewal, and recovery

### The CSR says CN=whatever. How do you stop a device asking for another identity?

The CA uses only the CSR's public key and self-signature. The subject is built from the validated device_id, the only
SAN is `urn:vitalsshield:device:<device_id>`, and extensions come from our fixed profile. A separate DEK signature
binds device_id, the token hash and the CSR hash; a failed proof burns the token (D34).

Evidence: `com.vitalsshield.server.enrollment.EnrollmentIT.csrAttributesIgnored`,
`com.vitalsshield.server.enrollment.EnrollmentIT.badDekProofRevokesToken`.

### What happens if the renewal response is lost on a flaky link?

Nothing breaks. The new leaf is stored as ISSUED_PENDING_USE and the old one stays ACTIVE until the first accepted
batch on the new one. The device renews again, and that revokes the unused leaf as REPLACED_BEFORE_USE (superseded on
the CRL). In the 10-minute soak on the PT3M demo profile: 600 batches all accepted, 10 renewals, activation 23.3 ms
to 41.7 ms (median 32.3 ms).

Evidence: `com.vitalsshield.server.renewal.RenewalIT.lostResponseRenewTwiceBeforeUse`,
`com.vitalsshield.server.renewal.ActivationConcurrencyIT.fiveParallelFirstBatchesSwitchOverOnce`.

### Can a stolen old certificate use the grace window?

Only for the 60 s after the real device's first batch on its successor, and only where the old key would be accepted
anyway. After grace, the handshake is refused, open sockets are closed, and a use more than 5 s after grace trips the
post-drain trap. Quarantine revokes RENEWED, ACTIVE and pending leaves together with no grace.

Evidence: `com.vitalsshield.server.renewal.RenewalIT.happyPathPendingActivationGraceAndEviction`,
`com.vitalsshield.server.renewal.QuarantineDuringRenewalIT.quarantineRevokesRenewedActiveAndPending`.

### What happens if a device is offline past its certificate's expiry?

It recovers by itself through Protocol C (D95). It asks for an HMAC challenge, signs it with its long-lived device
key (DEK), gets a new leaf with the same boot epoch and sequence numbers (D97), and resends the refused frame; no
clinician and no alert. A stolen expired leaf alone cannot do this, because Protocol C needs the DEK, not the leaf key.

Evidence: `com.vitalsshield.server.e2e.OfflineExpiryRecoveryE2E.streamSleepPastNotAfterResumeReEnrollsAutomatically`,
`com.vitalsshield.server.reenroll.ReEnrollIT.offlineExpiryHappyPathKeepsEpochAndSequence`.

## WebAuthn and the admin plane

### What exactly does the clinician approve with Touch ID?

A 32-byte challenge that is a hash of the action. For quarantine: purpose, device id, lookback minutes, reason and a
16-byte server nonce (D58); for provisioning: the device id, the token hash and its expiry. The parameters are held on
the server between begin and finish and the finish body is ignored, so the signature commits to exactly what runs,
once.

Evidence: `com.vitalsshield.server.admin.webauthn.StepUpIT.assertionForADifferentDigestIsRejectedAndNothingIsQuarantined`,
`com.vitalsshield.server.admin.webauthn.StepUpIT.bodyParametersAtFinishAreIgnored`,
`com.vitalsshield.server.admin.webauthn.StepUpIT.finishingTwiceIs410`.

### Your dev seed tool has a passkey on disk. Isn't that a back door?

No, because it has no clinician powers (D66). Its row is marked DEV_SEED, and it is refused for sign-in and every
step-up before anything changes; it can only finish provisioning started by the seed tool's own code, and only in the
local profile. Outside local, every DEV_SEED assertion is refused and the seed tool will not run.

Evidence: `com.vitalsshield.server.admin.webauthn.DevSeedPasskeyIT.devSeedCannotSignIn`,
`com.vitalsshield.server.admin.webauthn.DevSeedPasskeyIT.devSeedRefusedOutsideLocalProfile`.

### Apple passkeys report signCount 0. Doesn't that disable clone detection?

For synced passkeys, yes, and that is by design: the key is meant to be on all your Apple devices. We accept 0 and
still require a strictly increasing counter from authenticators that count (D61). The stronger guarantee is user
verification on every action, bound to its parameters.

Evidence: `com.vitalsshield.server.admin.webauthn.WebAuthnFlowsIT.syncedPasskeyCounterZeroIsAccepted`,
`com.vitalsshield.server.admin.webauthn.WebAuthnFlowsIT.counterRegressionIsRejected`.

### What does the admin plane not protect against?

An unlocked laptop with a live session can view the dashboard for up to 30 minutes idle or 8 hours total, but cannot
quarantine, restore or provision without a fresh Touch ID. The admin plane is plain HTTP on loopback, attestation is
not verified (D63), and sessions are in memory. CSRF is covered by a SameSite=Strict cookie and a required Origin
header.

Evidence: `com.vitalsshield.server.admin.webauthn.SessionStoreTest.idleExpiryAt30Minutes`,
`com.vitalsshield.server.admin.webauthn.CsrfAndCookieIT.postWithAForeignOriginIs403`,
`com.vitalsshield.server.gateway.MtlsListenerIT.allListenersOnLoopback`.

### Can someone edit the audit log?

Not without it showing. Entries are hash-chained under an advisory lock, and a database trigger rejects UPDATE and
DELETE (D62, D75); each entry is written in the same transaction as the action it records (D67). A database superuser
could still drop the trigger, which is why anchoring the chain in S3 Object Lock is in the design (not built).

Evidence: `com.vitalsshield.server.audit.AuditChainIT.tamperingOnePayloadBreaksTheChainAtThatEntry`,
`com.vitalsshield.server.audit.AuditImmutabilityIT.updateFails`,
`com.vitalsshield.server.quarantine.QuarantineAuditAtomicityIT.quarantineAndAuditAreAtomic`.

## Clinical engine and data integrity

### How do you stop a compromised sensor poisoning the baseline?

Only ACCEPTED resting batches that did not trigger an acute alert calibrate, and the baseline locks after its window
(10 in the demo, 30 by default), so slow drift cannot drag it. When a compromise is confirmed, quarantine marks the
window's batches QUARANTINED, resets any baseline built on them, and retracts only the alerts derived from them. A
device that lies plausibly from day one still builds a false baseline: signatures prove who sent the data, not that
it is true.

Evidence: `com.vitalsshield.server.clinical.CalibrationStatsTest.acuteTriggeringBatchesExcluded`,
`com.vitalsshield.server.quarantine.QuarantineIT.sanitizesDualTimestampResetsBaselineAndRetractsOnlyTaintedAlerts`,
`com.vitalsshield.server.e2e.ClinicalRetractionE2E.driftAlertRetractedAndRecalibratedAfterReEnrollment`.

### Can an ingest or an alert slip in after a quarantine?

No. Quarantine locks the device row FOR UPDATE and flips its state before the sanitize statement (D42), and every
clinical evaluation takes a key-share lock on that row first, so it either finishes before (and is retracted) or sees
the device is not ACTIVE. One global lock order across all transactions (D70, D82) prevents deadlocks:
`pg_stat_database.deadlocks` was 0 before and 0 after.

Evidence: `com.vitalsshield.server.quarantine.ConcurrentQuarantineIngestIT.noAcceptedRowSurvivesAndNothingIsAcceptedAfterCommit`,
`com.vitalsshield.server.clinical.InFlightRetractionIT.quarantineWaitsForTheInFlightEvaluationThenRetractsItsAlert`,
`com.vitalsshield.server.clinical.LockOrderIT.noDeadlockAcrossTwentyQuarantinesMidStream`.

## Operations and clocks

### Why do you care which clock a timestamp came from?

Because the clocks drift apart exactly when demos happen: after a laptop sleep, Postgres in the Docker VM was 13.6 s
behind the JVM, and an expiry sweep comparing a JVM time with Postgres NOW() ran late. The rule now is to compare a
timestamp only with the clock that wrote it (D89); `docs/CLOCK_INVENTORY.md` lists 31 comparisons, 10 of them
fixed (one in Phase 8.1, nine in Phase 9). A skew monitor shows the gap on the dashboard, amber above 2 s and red above 10 s (D98).

Evidence: `com.vitalsshield.server.clock.ClockDisciplineIT` (runs the JVM 10 minutes behind Postgres),
`com.vitalsshield.server.clock.ClockSkewMonitorTest.thresholds`. Stage: `scripts/stage/00-prestage.sh` (clock skew
line).

### How do you know it runs for more than five minutes?

Two soak runs. Phase 8.1 (PT4M leaves): 7,787 batches over 2 h 12 min, all accepted, 79 renewals, activation median
33 ms, until the laptop slept. Phase 10a.1 (PT3M demo profile, 10 minutes): 600 batches, 10 renewals, activation
23.3 / 32.3 / 41.7 ms (min / median / max), 0 anomalies, 0 deadlocks.

Evidence: the soak SQL in `docs/learning/phase-08-renewal.md` section 11;
`com.vitalsshield.server.e2e.NormalOperationNoAnomalyE2E.normalDeviceBehaviorRaisesNoAnomaly`.

## Limitations and "what would you do next"

### What is the residual risk you cannot close today?

Three things. A clone that re-enrolls while the real device is off goes unnoticed until the real device returns; a
software device key can be copied by anyone who reads the device's storage; and a clone copied just before a renewal
can win the renewal race (D102). The first two need a hardware secure element; the third needs the designed renewal
trap.

Evidence: D102; spec Section 2 rows 4 and 5.

### Does this run with more than one gateway?

Not today. Eviction, the deny-list, rate limits and CRL caches are per process; CRL numbers stay monotonic because the
database assigns them, but two gateways could briefly serve different CRLs (D30). Redis pub/sub for cross-gateway
eviction is designed, not built (D8), and the rate limiter keys on the TCP peer, so behind a load balancer the
per-address limit would act as a global one.

Evidence: D8, D29, D30; `docs/learning/phase-09-recovery.md` section 5.

