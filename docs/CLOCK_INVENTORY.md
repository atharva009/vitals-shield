# Clock inventory (DECISIONS 89)

Same-clock rule: compare a timestamp only with the clock that produced it. Three clocks exist in this system:

- **JVM**: the server's `Clock` bean (`PkiConfig.clock()`), read with `clock.instant()`. It writes `not_before`,
  `not_after`, `revoked_at`, `grace_expires_at`, `voided_at`, token `expires_at`, `max_renewal_horizon`, nonce
  `expires_at`, deny-list `deniedFrom`, and challenge `issued_at_ms`.
- **Postgres**: `now()` / `clock_timestamp()` in the Docker VM. It writes every `DEFAULT NOW()` column and every
  `= NOW()` assignment: `ingested_at`, `last_ingested_at`, `issued_at`, `activated_at`, `claimed_at`, `reserved_at`,
  `revoked_db_at` (V7 trigger), `created_at` of alerts.
- **Device**: the wearable's clock, which writes `measured_at` and `transmitted_at` in the signed payload.

The Phase 8 soak run showed the first two disagreeing by 13.6 s after a laptop sleep (Docker VM behind the host).
`ClockSkewMonitor` (DECISIONS 98) now measures that difference at boot and every 60 s.

The inventory below lists every place in `server/src/main` where a timestamp is compared with a clock or with another
timestamp, directly or through a bound parameter. Paths are relative to
`server/src/main/java/com/vitalsshield/server/`. FIXED rows were wrong before Phase 9. Each FIXED row has one
targeted assertion in `ClockDisciplineIT`, which runs the JVM clock 10 minutes behind Postgres, so the old comparison
fails it.

| # | Location | Values compared | Clocks | Verdict |
|---|---|---|---|---|
| 1 | `quarantine/QuarantineService.java:239` (sanitize CTE) | `ingested_at`, `measured_at` >= `:quarantineTs` - lookback | `ingested_at` Postgres; `measured_at` device; `:quarantineTs` was the JVM, now Postgres `now()` read in the same transaction | FIXED (`quarantineBindsQuarantineTsFromPostgresNowInItsTransaction`) |
| 2 | `enrollment/EnrollmentService.java:266` | token `expires_at` > now | `expires_at` JVM (also signed into the provisioning digest); was Postgres `NOW()`, now a JVM parameter | FIXED (`bootstrapTokenExpiryIsJudgedByTheJvmClock`) |
| 3 | `enrollment/EnrollmentService.java:267` | `claimed_at` < `NOW()` - 2 min | Postgres vs Postgres | OK |
| 4 | `renewal/RenewalSweepers.java:195` (nonce sweep) | nonce `expires_at` < now | `expires_at` JVM (issued_at_ms + 5 min); was Postgres `NOW()`, now a JVM parameter | FIXED (`nonceSweepUsesTheJvmClock`) |
| 5 | `renewal/RenewalSweepers.java:127,163` (expiry sweep) | `not_after` <= now | JVM vs JVM (fixed in Phase 8.1, DECISIONS 87) | FIXED in 8.1 (`expirySweepUsesTheJvmClock`) |
| 6 | `pki/trust/JdbcDenySource.java:36` (deny-list seed) | `not_after` > now - 1 day | `not_after` JVM; was Postgres `NOW()`, now a JVM parameter (`setClock`) | FIXED (`denyListSeedCutoffUsesTheJvmClock`) |
| 7 | `pki/trust/JdbcDenySource.java:51` | ledger `reserved_at` > `NOW()` - 2 days | Postgres vs Postgres | OK |
| 8 | `pki/CrlService.java:305` (VOIDED serials on the CRL) | ledger `reserved_at` > cutoff | `reserved_at` Postgres (`DEFAULT NOW()`); cutoff was a JVM instant, now `NOW()` minus the same interval | FIXED (`crlVoidedSerialWindowUsesPostgresNow`) |
| 9 | `pki/CrlService.java:321` (revoked certificates on the CRL) | `not_after` > now | JVM vs JVM | OK |
| 10 | `pki/IssuedSerialLedger.java:83-84` (stale reservation sweep) | `reserved_at` < `NOW()` - 2 min; writes `voided_at` | comparison Postgres vs Postgres; `voided_at` becomes a deny-list `deniedFrom` (compared with the JVM), so it was `NOW()`, now the JVM clock | FIXED (`staleReservationVoidedAtIsJvmTime`) |
| 11 | `renewal/RenewalService.java:295` and `renewal/CertificateActivationService.java:167` | `issued_at` and `activated_at` (issue-to-activation, renewal log, RenewalE2E timings) | were both JVM-written for renewals while enrollment's `issued_at` was `DEFAULT NOW()`; now both Postgres everywhere (renewal `DEFAULT NOW()`, activation `NOW()`, re-enrollment `NOW()`) | FIXED (`renewalIssuedAtAndActivatedAtArePostgresStamped`) |
| 12 | `admin/AdminOverviewService.java:91` and `dashboard/app/page.tsx` (`ago()`) | `last_ingested_at`, telemetry `ingested_at` vs "now" in the dashboard | were Postgres values against `server_time` (JVM); the overview now also returns `db_time` (Postgres `now()`), and the dashboard uses it for those columns | FIXED (`overviewReportsBothClocksAndTheSkewIsRed`) |
| 13 | `reenroll/ReEnrollService.java:357` (collision, DECISIONS 91) | `last_ingested_at` >= now - 30 s | Postgres vs Postgres `now()` | OK, new in Phase 9 (`collisionRecentIngestUsesPostgresNow`) |
| 14 | `reenroll/CollisionRule.java` via `ReEnrollService.java:288-301` | certificate `not_after`, `grace_expires_at` vs now | JVM vs JVM | OK, new in Phase 9 (`CollisionRuleTest`) |
| 15 | `signer/BackstopPoller.java:90-94` (DECISIONS 96) | `revoked_db_at` >= previous poll's `now()` - 30 s | Postgres vs Postgres. `revoked_at` is not compared: a direct-SQL revocation may set anything there, so a V7 trigger stamps `revoked_db_at` with `clock_timestamp()` | OK, new in Phase 9 (`BackstopPollerIT`, which sets `revoked_at` to 2020) |
| 16 | `renewal/RenewalService.java:246`, `reenroll/ReEnrollService.java:274` | `max_renewal_horizon` vs now | JVM (ProvisioningRecords writes it) vs JVM | OK |
| 17 | `gateway/CertStatusResolver.java:122,132` | `grace_expires_at`, `not_before`, `not_after` vs now | JVM vs JVM | OK |
| 18 | `pki/trust/DynamicMtlsTrustManager.java:113`, `CertificateDenyList.isDenied` | X.509 validity, `deniedFrom` vs now | JVM vs JVM (X.509 validity is written by `CertificateProfiles` with the same clock) | OK |
| 19 | `pki/PkiConfig.java` (`CertificateProfiles`) | certificate validity written | was `Clock.systemUTC()` beside the `Clock` bean, two JVM clock sources; now the bean | FIXED (single JVM clock; `renewalIssuedAtAndActivatedAtArePostgresStamped` handshakes under the skewed bean, which failed PKIX before) |
| 20 | `renewal/RenewalChallenge.java`, `reenroll/ReEnrollChallenge.java` | `issued_at_ms` vs now (60 s) | JVM vs JVM | OK |
| 21 | `anomaly/PostDrainTrap.java` | `grace_expires_at` + 5 s vs presented-at | JVM vs JVM | OK, new in Phase 9 |
| 22 | `anomaly/SequenceRegressionTrap.java` | rejection times in a 60 s window | JVM vs JVM | OK, new in Phase 9 |
| 23 | `renewal/CertificateActivationService.java` (grace eviction, `grace_expires_at`) | grace end vs now | JVM vs JVM | OK |
| 24 | `admin/AdminOverviewService.java` (`grace_ended`, `grace_ended_at`, renewal due) | `grace_expires_at`, `not_before`/`not_after` vs now | JVM vs JVM | OK |
| 25 | `telemetry/TelemetryPayloadValidator.java:61-64` | `transmitted_at` within 5 min of now; `measured_at` <= `transmitted_at` + 1 min | device vs JVM, by design: the freshness bound tolerates device clock error up to 5 minutes | OK (intentional cross-domain bound) |
| 26 | `clinical/ClinicalEvaluator.java` (resting sustain, drift) | `measured_at` vs `resting_since` | device vs device (`resting_since` is copied from `measured_at`) | OK |
| 27 | `quarantine/QuarantineService.java:85`, `HierarchyReconciler`, `devices.updated_at` | `retracted_at`, `revoked_at = NOW()` on a hierarchy rebuild, `updated_at` | written by Postgres. Rebuild `revoked_at` feeds deny-list `deniedFrom` (JVM), but every certificate it touches is under a revoked CA and fails PKIX first, so a skew of seconds cannot matter | OK (accepted, not changed) |
| 28 | `audit/AuditLog.java` | `created_at` | JVM, hash input only, never compared with a clock | OK |
| 29 | `clock/ClockSkewMonitor.java:50` | `clock_timestamp()` vs JVM | both, deliberately: this is the skew measurement (DECISIONS 98) | OK |
| 30 | `admin/KmsHealthMonitor`, `admin/webauthn/CeremonyStore`, `AdminSessionStore`, `BootStatusTracker` | in-memory expiry and timestamps | JVM only | OK |
