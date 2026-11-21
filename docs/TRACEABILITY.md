# Traceability matrix

Each claim in [spec v2](vitalsshield_technical_architecture_specification_v2.md) Section 2 ("Claims by layer") and
each "Live (tested)" item in Section 8 is mapped to the evidence for it. Evidence is one of:
- **test**: a fully qualified JUnit class and method, which passed in the run below;
- **manual record**: a file and section recording a run by hand;
- **command output**: a command and where its recorded output lives.

## Test run behind this matrix

`./gradlew test integrationTest e2eTest --rerun-tasks`, 2026-11-20 (Phase 10b.1), `BUILD SUCCESSFUL in 11m 8s`:

| Tier | Tests | Failures | Errors | Skipped |
|---|---|---|---|---|
| `test` (server) | 252 | 0 | 0 | 0 |
| `test` (simulator) | 21 | 0 | 0 | 0 |
| `test` (crypto-common) | 56 | 0 | 0 | 0 |
| `integrationTest` | 226 | 0 | 0 | 0 |
| `e2eTest` | 6 | 0 | 0 | 0 |
| **Total** | **561** | **0** | **0** | **0** |

## Drill run

`./gradlew :server:drillTest`, 2026-11-20 (Phase 10b.1), `BUILD SUCCESSFUL in 19s`: 1 test, 0 failures, test time
17.8 s. It restarts the Compose LocalStack, which wipes the KMS keys, so it is not part of the regular gate. Step
timings as printed by `LocalStackRestartDrill`:

```
DRILL t+ 1625 ms  server started (first boot)
DRILL t+ 1879 ms  1. enrolled and streamed 3 batches
DRILL t+15834 ms  2. docker compose restart localstack, healthy again
DRILL t+16294 ms  3. server restarted
DRILL t+16310 ms  3. REBUILT confirmed; trust file changed; old certificate refused at the handshake
DRILL t+16368 ms  4. reset-state, new token, re-enrolled at boot_epoch=2 with the same DEK, 1 batch accepted
```

The LocalStack restart takes about 14 s of the 16.4 s. The second boot logs `Hierarchy reconciliation: REBUILT`,
retires the 4 old keys, and the device's old certificate is refused at the handshake. Recovery in this drill is
re-provisioning through Protocol A (a new token, boot epoch 2, the DEK kept), because the rebuild clears every DEK
anchor.

Phase 10b.1 added 9 tests: `StoreUnavailableTest` (3, unit), `DbDownIngestIT` (1),
`RenewReEnrollRefusalsIT` (3), `ChallengeRateLimitIT` (1) and `MtlsListenerIT.revokedLeafGetsAlert46FromOpensslSClient`
(1). The first run of the suite in 10b.1 failed one existing test, `ClockDisciplineIT.staleReservationVoidedAtIsJvmTime`:
four assertions in that class truncated a 10-minute skew to whole minutes and expected 9, which fails whenever the
Docker VM clock runs a few milliseconds ahead of the host. They now compare with 10 minutes plus or minus 30 s; the
run above is the second run.

Every test reference in this file and in [`QA_DRILL.md`](QA_DRILL.md) was checked mechanically against the JUnit XML
of the test run above and of the drill run. A reference counts only if it names a passed test case, a method of a class whose recorded invocations
all passed (parameterized and repeated tests are recorded per invocation), or a whole class that passed.

## Section 2: claims by layer

### Layer 1: transport authentication

| Claim (spec v2) | § | Evidence type | Evidence |
|---|---|---|---|
| L1.1 Port 8443 accepts only TLS 1.3 and requires a client certificate. | 2.1 | test | `com.vitalsshield.server.gateway.MtlsListenerIT.tls12Refused`, `com.vitalsshield.server.gateway.MtlsListenerIT.noClientCertFailsHandshake` |
| L1.2 No TLS session on port 8443 resumes: every connection is a full handshake. [D26] | 2.1 | test | `com.vitalsshield.server.gateway.ResumptionIT.resumedSessionNeverReaches200AfterRevoke` |
| L1.3 The trust manager uses only the first certificate and ignores any client-supplied intermediate. | 2.1 | test | `com.vitalsshield.server.pki.trust.DynamicMtlsTrustManagerTest.clientSuppliedForgedIntermediateIsIgnored`, `com.vitalsshield.server.pki.trust.DynamicMtlsTrustManagerTest.acceptedIssuersIsOnlyCurrentDeviceIntermediate` |
| L1.4 A CA leaf, a leaf without digitalSignature or EKU clientAuth, or a wrong AKI is rejected at the handshake. | 2.1 | test | `com.vitalsshield.server.pki.trust.DynamicMtlsTrustManagerTest.caTrueLeafFails`, `com.vitalsshield.server.pki.trust.DynamicMtlsTrustManagerTest.ekuWithoutClientAuthFails`, `com.vitalsshield.server.pki.trust.DynamicMtlsTrustManagerTest.leafFromDifferentCaWithIdenticalDnFails` |
| L1.5 A leaf from a previous (rebuilt) hierarchy is rejected even with the same issuer DN. | 2.1 | test | `com.vitalsshield.server.gateway.MtlsListenerIT.oldHierarchyLeafRejected`, `com.vitalsshield.server.pki.trust.DynamicMtlsTrustManagerTest.leafFromDifferentCaWithIdenticalDnFails` |
| L1.6 A deny-listed certificate is rejected at the handshake with no database access. [D24] | 2.1 | test | `com.vitalsshield.server.pki.trust.DynamicMtlsTrustManagerTest.denyListedLeafFails`, `com.vitalsshield.server.pki.trust.DynamicMtlsTrustManagerTest.anchorsAreReadOnEveryCall`, `com.vitalsshield.server.gateway.MtlsListenerIT.revokedLeafRejectedOnImmediateReconnect` |
| L1.7 The post-handshake gate re-checks the deny-list after every completed handshake. [D24] | 2.1 | test | `com.vitalsshield.server.gateway.ResumptionIT.resumedSessionNeverReaches200AfterRevoke` |
| L1.8 A status change is refused on the next request on the same connection (no cache). [D23] | 2.1 | test | `com.vitalsshield.server.gateway.MtlsListenerIT.dbStatusChangeVisibleToNextRequestOnSameConnection`, `com.vitalsshield.server.e2e.TelemetryPerRequest403E2E.ingestOnSameConnectionAfterRevokeIs403` |
| L1.9 Revoking a certificate closes its live sockets; revoke-to-close latency under 500 ms. [D11] | 2.1 | test | `com.vitalsshield.server.gateway.MtlsListenerIT.revokeClosesLiveKeepAliveSocket`, `com.vitalsshield.server.e2e.SpineE2E.spineFiveTimes` (asserts the latency; this run: `[1875, 1288, 2670, 1365, 1353]` µs) |
| L1.10 A rejected client certificate receives TLS alert 46 (`certificate_unknown`). [D37] | 2.1 | test | `com.vitalsshield.server.gateway.MtlsListenerIT.revokedLeafGetsAlert46FromOpensslSClient` (Phase 10b.1: `openssl s_client` gets HTTP 200 before the revocation, then `ssl/tls alert certificate unknown ... SSL alert number 46` and exit 1), `com.vitalsshield.server.pki.trust.DynamicMtlsTrustManagerTest.denyListedLeafFails` |

### Layer 2: origin authentication and at-rest integrity

| Claim (spec v2) | § | Evidence type | Evidence |
|---|---|---|---|
| L2.1 A batch is accepted only if its JWS verifies with the key of the connection's TLS certificate. | 2.1 | test | `com.vitalsshield.server.telemetry.TelemetryIngestIT.differentKeyWithCorrectX5tIsSigInvalid`, `com.vitalsshield.server.telemetry.TelemetryIngestIT.x5tOfAnotherCertIsCertMismatch`, `com.vitalsshield.crypto.JwsPolicyTest.wrongKeyRejected` |
| L2.2 Header exactly ES256, the telemetry typ and a matching `x5t#S256`; jwk, jku, x5c, x5u and crit rejected. [D43] | 2.1 | test | `com.vitalsshield.crypto.JwsPolicyTest.forbiddenHeaderParametersRejected`, `com.vitalsshield.crypto.JwsPolicyTest.otherAlgorithmsRejected`, `com.vitalsshield.crypto.JwsPolicyTest.wrongTypRejected`, `com.vitalsshield.crypto.JwsPolicyTest.missingOrWrongX5tRejected` |
| L2.3 A payload naming another device is rejected with 403 `DEVICE_MISMATCH`. | 2.1 | test | `com.vitalsshield.server.telemetry.TelemetryIngestIT.otherDevicesIdIs403`, `com.vitalsshield.server.telemetry.TelemetryPayloadValidatorTest.otherDeviceIs403` |
| L2.4 Unknown, missing or null payload fields are rejected. [D43] | 2.1 | test | `com.vitalsshield.server.telemetry.TelemetryPayloadValidatorTest.unknownTopLevelFieldRejected`, `com.vitalsshield.server.telemetry.TelemetryPayloadValidatorTest.unknownMetricRejected`, `com.vitalsshield.server.telemetry.TelemetryPayloadValidatorTest.metricsRequiredAndTyped` |
| L2.5 The compact JWS is stored, so origin can be re-verified at rest. | 2.1 | test | `com.vitalsshield.server.telemetry.TelemetryIngestIT.storedJwsReverifiesOfflineAgainstStoredCert` |

### Layer 3: provisioning and registry integrity

| Claim (spec v2) | § | Evidence type | Evidence |
|---|---|---|---|
| L3.1 Every passkey row carries a KMS Key #4 anchor, verified before every assertion. [D56] | 2.1 | test | `com.vitalsshield.server.admin.webauthn.PasskeyAnchorIT.swappedPublicKeyFailsWithAnAnchorErrorAndUntouchedRowsVerify`, `com.vitalsshield.server.admin.webauthn.PasskeyAnchorIT.reassignedClinicianFailsTheAnchor` |
| L3.2 Protocol A re-verifies the stored provisioning assertion before any KMS signature. [D57] | 2.1 | test | `com.vitalsshield.server.admin.webauthn.ProvisioningReverifyIT.sqlForgedTokenIsRefusedWithoutAnyKmsSign`, `com.vitalsshield.server.admin.webauthn.ProvisioningReverifyIT.alteredClientJsonIsRefused`, `com.vitalsshield.server.admin.webauthn.ProvisioningReverifyIT.provisionedThroughTheApiEnrolls` |
| L3.3 Enrollment stores a KMS Key #4 DEK anchor; re-enrollment re-verifies it (SQL edit gives 403). | 2.1 | test | `com.vitalsshield.server.enrollment.EnrollmentIT.dekAnchorDetectsTamper`, `com.vitalsshield.server.reenroll.ReEnrollIT.tamperedAnchorAndUnknownDeviceAreTheSame403`, `com.vitalsshield.server.admin.AdminOverviewIT.dekTamperShowsUnverified` |
| L3.4 Quarantine and restore-active each need a fresh assertion over the action and its server-held parameters. [D58] | 2.1 | test | `com.vitalsshield.server.admin.webauthn.StepUpIT.assertionForADifferentDigestIsRejectedAndNothingIsQuarantined`, `com.vitalsshield.server.admin.webauthn.StepUpIT.bodyParametersAtFinishAreIgnored`, `com.vitalsshield.server.admin.webauthn.StepUpIT.restoreActiveOnlyFromReauthRequired` |
| L3.5 After the first passkey exists, the setup code authorizes nothing. [D60] | 2.1 | test | `com.vitalsshield.server.admin.webauthn.WebAuthnFlowsIT.secondRegistrationWithoutSessionIs401EvenWithTheSetupCode`, `com.vitalsshield.server.admin.webauthn.AuthModeFlagIT.webauthnModeRefusesTheBearerExceptForTheFirstPasskey` |
| L3.6 The dev seed passkey cannot sign in or approve step-ups, and is refused outside `local` and `demo`. [D66, D99] | 2.1 | test | `com.vitalsshield.server.admin.webauthn.DevSeedPasskeyIT.devSeedCannotSignIn`, `com.vitalsshield.server.admin.webauthn.DevSeedPasskeyIT.devSeedCannotApproveQuarantine`, `com.vitalsshield.server.admin.webauthn.DevSeedPasskeyIT.devSeedRefusedOutsideLocalProfile`, `com.vitalsshield.server.admin.webauthn.DevSeedProfileTest.localAndDemoAllowDevSeedNothingElseDoes` |

### Layer 4: device credential hierarchy

| Claim (spec v2) | § | Evidence type | Evidence |
|---|---|---|---|
| L4.1 A device renews at 2/3 of validity without human action, proving the current OLK and the new key. [D83] | 2.1 | test | `com.vitalsshield.server.renewal.RenewalIT.happyPathPendingActivationGraceAndEviction`, `com.vitalsshield.server.renewal.RenewalIT.proofRejections`, `com.vitalsshield.simulator.RenewalDueRuleTest.twelveHourLeafRenewsAtEightHours`, `com.vitalsshield.server.e2e.RenewalE2E.streamsThroughRolloversThenQuarantineEndsIt` |
| L4.2 Renewal refused when not ACTIVE, unassigned or past the horizon; re-enrollment refused when not ACTIVE, unassigned (409 DEVICE_UNASSIGNED) or past the horizon. | 2.1 | test | `com.vitalsshield.server.renewal.RenewalIT.deviceAndAssignmentRejections`, `com.vitalsshield.server.reenroll.ReEnrollIT.reauthRequiredDeviceIs403AndItsNonceCannotBeReplayed`, `com.vitalsshield.server.reenroll.RenewReEnrollRefusalsIT.reEnrollWithNoActiveAssignmentIs409DeviceUnassigned`, `com.vitalsshield.server.reenroll.ReEnrollIT.horizonExceededIs409` |
| L4.3 A device whose leaf expired offline recovers through Protocol C, keeping epoch and sequence. [D95, D97] | 2.1 | test | `com.vitalsshield.server.reenroll.ReEnrollIT.offlineExpiryHappyPathKeepsEpochAndSequence`, `com.vitalsshield.server.reenroll.ReEnrollIT.midStreamOutsideValidityRecoversAndResendsTheSameFrame`, `com.vitalsshield.server.e2e.OfflineExpiryRecoveryE2E.streamSleepPastNotAfterResumeReEnrollsAutomatically` |
| L4.4 An expired leaf without the DEK cannot re-enroll. | 2.1 | test | `com.vitalsshield.server.reenroll.ReEnrollIT.wrongDekSignatureIs400`, `com.vitalsshield.server.reenroll.ReEnrollIT.csrKeyOfAnOldCertificateIs400` |

### Layer 5: split-brain anomaly detection

| Claim (spec v2) | § | Evidence type | Evidence |
|---|---|---|---|
| L5.1 A re-enrollment while a usable certificate has a live socket or a recent ingest raises `REENROLL_COLLISION`. [D91] | 2.1 | test | `com.vitalsshield.server.reenroll.CollisionIT.clonedDekReEnrollingWhileTheDeviceStreamsIsReauthRequired`, `com.vitalsshield.server.reenroll.CollisionRuleTest.usableCertPlusLiveSocketFires`, `com.vitalsshield.server.reenroll.CollisionRuleTest.usableCertPlusRecentIngestFires` |
| L5.2 An expired certificate alone never counts as a collision. [D91] | 2.1 | test | `com.vitalsshield.server.reenroll.CollisionIT.expiredCertificateWithAnIngestFiveSecondsAgoIsNormalRecovery`, `com.vitalsshield.server.reenroll.CollisionRuleTest.expiredCertPlusRecentIngestDoesNotFire` |
| L5.3 Three replay-type rejections with distinct batch ids in 60 s raise `SEQUENCE_REGRESSION`; retries never count. [D93] | 2.1 | test | `com.vitalsshield.server.anomaly.SequenceRegressionTrapTest.twoInSixtySecondsDoNotFireThreeDo`, `com.vitalsshield.server.anomaly.SequenceRegressionTrapTest.idempotentRetriesOfTheSameBatchNeverCount`, `com.vitalsshield.server.anomaly.CloneTrapIT.twoCopiesStreamingTripTheTrapThenRestoreLetsOnlyTheOriginalBack` |
| L5.4 A RENEWED certificate presented more than 5 s after grace with an ACTIVE successor raises `POST_DRAIN_USE`. [D94] | 2.1 | test | `com.vitalsshield.server.anomaly.PostDrainTrapIT.oldCertificateWithinGraceIsFineAfterGracePlusSixIsAnAnomaly`, `com.vitalsshield.server.anomaly.PostDrainTrapTest.sixSecondsAfterGraceWithActiveSuccessorFires`, `com.vitalsshield.server.anomaly.PostDrainTrapTest.fourSecondsAfterGraceDoesNotFire` |
| L5.5 An epoch above the stored one raises `BOOT_EPOCH_INVALID`; below it without a restore, `BOOT_EPOCH_REGRESSION`. | 2.1 | test | `com.vitalsshield.server.reenroll.ReEnrollIT.epochAboveStoredIsInvalidAndRaisesTheAnomaly`, `com.vitalsshield.server.reenroll.ReEnrollIT.epochBelowStoredIsRegressionThenRestoreAllowsResync`, `com.vitalsshield.server.reenroll.EpochRulesTest.presentedAboveStoredIsInvalidEvenWithResync` |
| L5.6 The anomaly response revokes every usable certificate, closes sockets, sets REAUTH_REQUIRED, writes alert and audit, changes no telemetry. [D92] | 2.1 | test | `com.vitalsshield.server.reenroll.CollisionIT.clonedDekReEnrollingWhileTheDeviceStreamsIsReauthRequired`, `com.vitalsshield.server.reenroll.ReEnrollIT.epochAboveStoredIsInvalidAndRaisesTheAnomaly`, `com.vitalsshield.server.anomaly.CloneTrapIT.twoCopiesStreamingTripTheTrapThenRestoreLetsOnlyTheOriginalBack` |
| L5.7 Normal operation with all traps on raises no anomaly. [D100] | 2.1 | test | `com.vitalsshield.server.e2e.NormalOperationNoAnomalyE2E.normalDeviceBehaviorRaisesNoAnomaly` (270 batches, 37 renewals, 1 re-enrollment, 5 idempotent retries, 0 anomalies); soak runs in `docs/DEMO_RUNBOOK.md` "Soak results" (command output) |

### Layer 6: replay and ordering

| Claim (spec v2) | § | Evidence type | Evidence |
|---|---|---|---|
| L6.1 Each (device, boot epoch, sequence) is accepted at most once. | 2.1 | test | `com.vitalsshield.server.telemetry.ReplayWindowPropertyIT.endpointMatchesModel`, `com.vitalsshield.server.telemetry.ConcurrentDuplicateIT.sameSequenceDifferentBatchesAcceptsOne` |
| L6.2 Up to 63 below the highest seen is accepted once if unseen; more than 63 below is `SEQUENCE_TOO_OLD`. | 2.1 | test | `com.vitalsshield.server.telemetry.ReplayWindowModelTest.outOfOrderWithin64`, `com.vitalsshield.server.telemetry.ReplayWindowModelTest.tooOld64And65Behind`, `com.vitalsshield.server.telemetry.ReplayWindowModelTest.gapOfExactly64ResetsBitmap`, `com.vitalsshield.server.telemetry.ReplayWindowPropertyIT.endpointMatchesModel` |
| L6.3 Concurrent duplicates of one frame give exactly one row and no abort. | 2.1 | test | `com.vitalsshield.server.telemetry.ConcurrentDuplicateIT.twentyIdenticalFramesStoreOneRow` |
| L6.4 A retry with the same batch id, payload hash and epoch returns 200 with `idempotent_retry: true`. | 2.1 | test | `com.vitalsshield.server.telemetry.ConcurrentDuplicateIT.twentyIdenticalFramesStoreOneRow`, `com.vitalsshield.server.e2e.NormalOperationNoAnomalyE2E.normalDeviceBehaviorRaisesNoAnomaly` |
| L6.5 A batch id reused with another payload or sequence is 409 `BATCH_ID_REUSED`. | 2.1 | test | `com.vitalsshield.server.telemetry.ConcurrentDuplicateIT.batchIdReusedUnderNewSequenceConsumesThatSequence` |
| L6.6 Sequence numbers below 1 are rejected. [D40] | 2.1 | test | `com.vitalsshield.server.telemetry.TelemetryPayloadValidatorTest.sequenceAndEpochMustBePositive` |

## Section 8: "Live (tested)" items

| Claim (spec v2 Section 8) | § | Evidence type | Evidence |
|---|---|---|---|
| Four P-256 KMS keys recorded in `kms_keys`; DIGEST signing | 8 | test | `com.vitalsshield.server.kms.KmsSignerIT.signsSha256DigestAndVerifiesWithJca`, `com.vitalsshield.server.kms.KmsSmokeIT.signatureIsDer`, `com.vitalsshield.server.db.SchemaMigrationIT.oneActiveKeyPerPurpose` |
| RFC 5280 profiles for every certificate, checked with OpenSSL | 8 | test | `com.vitalsshield.server.pki.CertificateProfileTest` (whole class), `com.vitalsshield.server.pki.PkiOpensslIT.deviceLeafVerifiesForClientAuthOnly`, `com.vitalsshield.server.pki.PkiOpensslIT.gatewayLeafVerifiesForServerAuthOnly`, `com.vitalsshield.server.pki.PkiOpensslIT.crlsVerify` |
| First boot builds, second boot no-op, local rebuild on key loss; non-local profiles fail closed | 8 | test | `com.vitalsshield.server.pki.ReconciliationIT.firstBootBuildsHierarchy`, `com.vitalsshield.server.pki.ReconciliationIT.secondBootIsNoOp`, `com.vitalsshield.server.pki.ReconciliationIT.pendingDeletionKeyTriggersFullRebuild`, `com.vitalsshield.server.pki.ReconciliationIT.prodProfileFailsClosed` |
| Gateway TLS key in memory, never on disk; boot steps in order, listeners last | 8 | test | `com.vitalsshield.server.boot.BootSequenceIT.noPrivateKeyOnDisk`, `com.vitalsshield.server.boot.BootSequenceIT.stepsRunInOrder`, `com.vitalsshield.server.gateway.MtlsListenerIT.bootStepsInOrder` |
| KMS health monitor; canonical encodings against golden vectors | 8 | test | `com.vitalsshield.server.admin.KmsHealthMonitorTest` (whole class), `com.vitalsshield.server.admin.AdminOverviewIT.kmsKeyLossIsReported`, `com.vitalsshield.crypto.encoding.CanonicalEncodingsTest` (whole class) |
| Serials: random, positive, at most 20 octets, unique | 8 | test | `com.vitalsshield.server.pki.SerialAllocatorTest` (whole class), `com.vitalsshield.server.pki.CertificateProfileTest.serialsArePositiveAtMost20OctetsAndUnique` |
| Every signed serial RECORDED or VOIDED (ledger) | 8 | test | `com.vitalsshield.server.pki.SerialReservationIT.everyCertificateHasLedgerRow`, `com.vitalsshield.server.pki.SerialReservationIT.crashAfterSignIsVoidedByBootSweep`, `com.vitalsshield.server.pki.SerialReservationIT.reclaimRaceLoserIsVoidedAndOnCrl` |
| Rebuild after a real LocalStack restart ("Live (manual verification)": drill tier, outside the regular gate) | 8 | test (drill tier) | `com.vitalsshield.server.drill.LocalStackRestartDrill.localStackRestartRebuildsAndDeviceRecovers`, run in Phase 10b.1; step timings in "Drill run" above |
| Three loopback listeners, per-port path enforcement | 8 | test | `com.vitalsshield.server.gateway.MtlsListenerIT.allListenersOnLoopback`, `com.vitalsshield.server.gateway.MtlsListenerIT.wrongPortReturns404`, `com.vitalsshield.server.gateway.PortEnforcementWebFilterTest` (whole class), `com.vitalsshield.server.admin.webauthn.CsrfAndCookieIT.adminPortAnswersOnIpv6Loopback` |
| Live socket eviction under 500 ms; deny-list survives restart; 30 s deny-list refresh | 8 | test | `com.vitalsshield.server.e2e.SpineE2E.spineFiveTimes`, `com.vitalsshield.server.gateway.MtlsListenerIT.denyListSurvivesRestart`, `com.vitalsshield.server.pki.trust.CertificateDenyListTest.refreshAddsNewRows`, `com.vitalsshield.server.pki.trust.CertificateDenyListTest.refreshNeverRemovesEntries` |
| TLS alert 46 for a revoked client certificate, asserted on `openssl s_client` output [D37] | 8 | test | `com.vitalsshield.server.gateway.MtlsListenerIT.revokedLeafGetsAlert46FromOpensslSClient` |
| Backstop poller on `revoked_db_at` | 8 | test | `com.vitalsshield.server.signer.BackstopPollerIT.directSqlRevocationClosesTheLiveSocketWithinFourSeconds` |
| CRLs cached, never signed by a GET, republished after revocation and coalesced | 8 | test | `com.vitalsshield.server.gateway.MtlsListenerIT.crlGetsDoNotSign`, `com.vitalsshield.server.gateway.MtlsListenerIT.crlRepublishedOnRevoke`, `com.vitalsshield.server.gateway.MtlsListenerIT.crlBurstCoalesced`, `com.vitalsshield.server.pki.PkiOpensslIT.revokedLeafAppearsOnIntermediateCrl` |
| Provisioning begin/finish; token claim, reclaim, burn, return; enrollment 503 with Retry-After | 8 | test | `com.vitalsshield.server.enrollment.EnrollmentIT.tokenSingleUse`, `com.vitalsshield.server.enrollment.EnrollmentIT.staleClaimingReclaimed`, `com.vitalsshield.server.enrollment.EnrollmentIT.badDekProofRevokesToken`, `com.vitalsshield.server.enrollment.EnrollmentIT.kmsFailureReturnsToken` |
| Renewal and re-enrollment 503 with a 3 to 8 s Retry-After when KMS signing fails, serial VOIDED [D34, D38] | 8 | test | `com.vitalsshield.server.reenroll.RenewReEnrollRefusalsIT.renewalKmsFailureIs503WithRetryAfterAndTheSerialIsVoided`, `com.vitalsshield.server.reenroll.RenewReEnrollRefusalsIT.reEnrollKmsFailureIs503WithRetryAfterAndTheSerialIsVoided` |
| DEK proof, CSR proof, DEK anchor; boot epoch 1 then +1 on re-provision | 8 | test | `com.vitalsshield.server.enrollment.EnrollmentIT.happyPathEnrolls`, `com.vitalsshield.server.enrollment.EnrollmentIT.badCsrSignatureRevokesToken`, `com.vitalsshield.server.enrollment.EnrollmentIT.reprovisionRevokesPriorEvictsAndBumpsEpoch`, `com.vitalsshield.server.enrollment.BootEpochRuleTest` (whole class) |
| Simulator enroll and persistence; dev seed tool restrictions | 8 | test | `com.vitalsshield.server.enrollment.SimulatorEnrollIT.enrollPersistAndPing`, `com.vitalsshield.server.enrollment.SimulatorEnrollIT.restartDoesNotReenroll`, `com.vitalsshield.devtools.SeedDemoDeviceTest` (whole class) |
| Passkey registration with the setup code, discoverable sign-in, sessions with idle and absolute limits | 8 | test | `com.vitalsshield.server.admin.webauthn.WebAuthnFlowsIT.firstRegistrationNeedsTheSetupCode`, `com.vitalsshield.server.admin.webauthn.WebAuthnFlowsIT.signInSetsAStrictHttpOnlyCookie`, `com.vitalsshield.server.admin.webauthn.SessionStoreTest.idleExpiryAt30Minutes`, `com.vitalsshield.server.admin.webauthn.SessionStoreTest.activityKeepsItAliveUntilTheAbsoluteLimit` |
| SameSite=Strict cookie and Origin check; 307 from 127.0.0.1 to localhost | 8 | test | `com.vitalsshield.server.admin.webauthn.CsrfAndCookieIT.postWithAForeignOriginIs403`, `com.vitalsshield.server.admin.webauthn.CsrfAndCookieIT.postWithoutOriginIs403`, `com.vitalsshield.server.admin.webauthn.CsrfAndCookieIT.htmlOn127IsRedirectedToLocalhost` |
| Signature counter rule; ceremony expiry and single use (410) | 8 | test | `com.vitalsshield.server.admin.webauthn.CounterRuleTest` (whole class), `com.vitalsshield.server.admin.webauthn.WebAuthnFlowsIT.counterRegressionIsRejected`, `com.vitalsshield.server.admin.webauthn.CeremonyStoreTest.expiresAfterTwoMinutes`, `com.vitalsshield.server.admin.webauthn.StepUpIT.finishingTwiceIs410` |
| Real Touch ID (registration, provisioning, step-up quarantine) | 8 | manual record | `docs/learning/phase-06-manual-touchid.md` (D80) |
| JWS verification with the TLS key only, header allow-list, certificate binding, strict payload | 8 | test | `com.vitalsshield.crypto.JwsPolicyTest` (whole class), `com.vitalsshield.server.telemetry.TelemetryIngestIT.differentKeyWithCorrectX5tIsSigInvalid`, `com.vitalsshield.server.telemetry.TelemetryPayloadValidatorTest` (whole class) |
| Ingest 503 STORE_UNAVAILABLE with a 3 to 8 s Retry-After while the database is stopped mid-stream; the same frame accepted after restart; no batch lost or duplicated [D103] | 8 | test | `com.vitalsshield.server.telemetry.DbDownIngestIT.databaseOutageMidStreamIs503ThenTheSameFrameIsAcceptedAndNothingIsLostOrDuplicated`, `com.vitalsshield.server.gateway.StoreUnavailableTest` (whole class) |
| Replay CTE against a model over 2000 random operations; concurrent duplicates; idempotent retries; BATCH_ID_REUSED; ASSIGNMENT_CHANGED | 8 | test | `com.vitalsshield.server.telemetry.ReplayWindowPropertyIT.endpointMatchesModel`, `com.vitalsshield.server.telemetry.ConcurrentDuplicateIT` (whole class), `com.vitalsshield.server.telemetry.TelemetryIngestIT.staleAssignmentIs409WithCurrentId` |
| Renew challenge bound to the TLS serial; body binding; proof checks; nonce replay refused | 8 | test | `com.vitalsshield.server.renewal.RenewalIT.challengeAndBindingRejections`, `com.vitalsshield.server.renewal.RenewalIT.proofRejections`, `com.vitalsshield.server.renewal.RenewalChallengeTest` (whole class) |
| First-use activation; concurrent activation; grace, grace eviction, per-request refusal after grace | 8 | test | `com.vitalsshield.server.renewal.RenewalIT.happyPathPendingActivationGraceAndEviction`, `com.vitalsshield.server.renewal.ActivationConcurrencyIT.fiveParallelFirstBatchesSwitchOverOnce`, `com.vitalsshield.server.renewal.RenewalIT.perRequestCheckRefusesRenewedCertOnceTheStoredGraceHasPassed` |
| Lost response leads to REPLACED_BEFORE_USE; renewal on ASSIGNMENT_CHANGED; quarantine during renewal; crash after sign voided | 8 | test | `com.vitalsshield.server.renewal.RenewalIT.lostResponseRenewTwiceBeforeUse`, `com.vitalsshield.server.renewal.AssignmentChangedRenewalIT.assignmentChangeTriggersRenewal`, `com.vitalsshield.server.renewal.QuarantineDuringRenewalIT.quarantineRevokesRenewedActiveAndPending`, `com.vitalsshield.server.renewal.RenewalIT.crashAfterSignIsVoidedBySweepAndListed` |
| Expiry sweep, including the boot run; simulator renewal due rule and pending store | 8 | test | `com.vitalsshield.server.renewal.ExpiredSweeperIT` (whole class), `com.vitalsshield.simulator.RenewalDueRuleTest` (whole class), `com.vitalsshield.simulator.SimulatorStateStoreTest.pendingIsSavedPromotedAndDiscarded` |
| Re-enroll challenge (stateless HMAC, separate key); rate limiter, unit and endpoint (11th challenge in a minute is 429 with Retry-After) | 8 | test | `com.vitalsshield.server.reenroll.ChallengeTagTest` (whole class), `com.vitalsshield.server.reenroll.RateLimiterTest` (whole class), `com.vitalsshield.server.reenroll.ChallengeRateLimitIT.eleventhChallengeWithinAMinuteIs429WithRetryAfter` |
| Offline-expiry recovery; mid-stream recovery; epoch rules; forged DEK refused | 8 | test | `com.vitalsshield.server.reenroll.ReEnrollIT` (whole class), `com.vitalsshield.server.reenroll.EpochRulesTest` (whole class), `com.vitalsshield.server.e2e.OfflineExpiryRecoveryE2E.streamSleepPastNotAfterResumeReEnrollsAutomatically` |
| Collision rule; sequence-regression trap; post-drain trap; anomaly response; no anomaly in normal operation | 8 | test | `com.vitalsshield.server.reenroll.CollisionRuleTest` (whole class), `com.vitalsshield.server.anomaly.SequenceRegressionTrapTest` (whole class), `com.vitalsshield.server.anomaly.PostDrainTrapIT.oldCertificateWithinGraceIsFineAfterGracePlusSixIsAnAnomaly`, `com.vitalsshield.server.e2e.NormalOperationNoAnomalyE2E.normalDeviceBehaviorRaisesNoAnomaly` |
| Plausibility and perfusion classification; activity context with the 5-minute resting rule | 8 | test | `com.vitalsshield.server.telemetry.TelemetryClassifierTest` (whole class), `com.vitalsshield.server.clinical.ActivityClassifierTest` (whole class), `com.vitalsshield.server.clinical.ClinicalEngineIT.restingNeedsFiveSustainedMinutes` |
| Acute alerts with dedupe; low-perfusion critical streak; calibration with sample SD and floors; drift with lineage; streak restart | 8 | test | `com.vitalsshield.server.clinical.AcuteRulesTest` (whole class), `com.vitalsshield.server.clinical.AlertDedupeTest` (whole class), `com.vitalsshield.server.clinical.DegradedCriticalStreakTest` (whole class), `com.vitalsshield.server.clinical.CalibrationStatsTest` (whole class), `com.vitalsshield.server.clinical.DriftRuleTest` (whole class), `com.vitalsshield.server.clinical.ClinicalEngineIT` (whole class) |
| Evaluation queue cap and counters; acknowledge and resolve with audit | 8 | test | `com.vitalsshield.server.clinical.ClinicalQueueCapIT.thirdBatchOverflowsAndStaysUnevaluated`, `com.vitalsshield.server.clinical.AlertActionsIT` (whole class) |
| Lock-then-sanitize quarantine with no ACCEPTED row surviving a concurrent ingest | 8 | test | `com.vitalsshield.server.quarantine.ConcurrentQuarantineIngestIT.noAcceptedRowSurvivesAndNothingIsAcceptedAfterCommit` |
| Dual-timestamp sanitize, baseline reset, scoped retraction (including in-flight evaluations) | 8 | test | `com.vitalsshield.server.quarantine.QuarantineIT.sanitizesDualTimestampResetsBaselineAndRetractsOnlyTaintedAlerts`, `com.vitalsshield.server.clinical.QuarantineRetractionIT.quarantineRetractsExactlyTheTaintedAlerts`, `com.vitalsshield.server.clinical.InFlightRetractionIT.quarantineWaitsForTheInFlightEvaluationThenRetractsItsAlert`, `com.vitalsshield.server.e2e.ClinicalRetractionE2E.driftAlertRetractedAndRecalibratedAfterReEnrollment` |
| Global lock order with no deadlock under mixed load; quarantine and audit atomic | 8 | test | `com.vitalsshield.server.clinical.LockOrderIT.noDeadlockAcrossTwentyQuarantinesMidStream`, `com.vitalsshield.server.quarantine.QuarantineAuditAtomicityIT` (whole class) |
| Audit hash chain, chain verification, append-only triggers | 8 | test | `com.vitalsshield.server.audit.AuditChainIT` (whole class), `com.vitalsshield.server.audit.AuditImmutabilityIT` (whole class) |
| Same-clock rule for every fixed comparison; skew classification; both clocks on the overview | 8 | test | `com.vitalsshield.server.clock.ClockDisciplineIT` (whole class), `com.vitalsshield.server.clock.ClockSkewMonitorTest` (whole class) |
| Dashboard served on the admin port, path traversal refused, CSP with inline-script hashes | 8 | test | `com.vitalsshield.server.admin.DashboardServingIT.indexServedOnAdminPortWithSecurityHeaders`, `com.vitalsshield.server.admin.DashboardServingIT.traversalIs404`, `com.vitalsshield.server.admin.DashboardServingIT.dashboardIs404OnMtlsAndPublicPorts` |
| Overview API including needs_attention, CERT_EXPIRED_NO_SUCCESSOR and clock skew | 8 | test | `com.vitalsshield.server.quarantine.QuarantineAuditAtomicityIT.failureInsideAuditAppendRollsBackQuarantine`, `com.vitalsshield.server.renewal.ExpiredSweeperIT.activeCertExpiresWithoutSuccessor`, `com.vitalsshield.server.clock.ClockDisciplineIT.overviewReportsBothClocksAndTheSkewIsRed` |
| Demo profile effective values | 8 | test | `com.vitalsshield.server.config.DemoProfileTest.demoValuesWinAndLocalValuesAreInherited`, `com.vitalsshield.server.admin.AdminAuthIT.bootStatusIsOpen` |
| Nine-beat stage rehearsal; release scan | 8 | command output | `node scripts/rehearsal/rehearse.mjs ...` recorded in `docs/DEMO_RUNBOOK.md` "Rehearsal record"; the history scan in `docs/RELEASE_CHECK.md` |
