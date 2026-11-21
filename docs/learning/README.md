# VitalsShield learning notes

Notes for the developer, written to explain the system from first principles and to prepare for PKI-focused
questions. Each phase note describes the code as built, points at the spec
(`docs/vitalsshield_technical_architecture_specification.md`) by section number, and says where the code differs
from the spec.

## Index

| Phase | Note | Commit |
| :--- | :--- | :--- |
| 0 | [Scaffold: build, Compose stack, schema, KMS smoke tests](phase-00-scaffold.md) | `d23ebe7`, `7d8841d` |
| 1 | [PKI core: KMS-backed CA hierarchy, profiles, CRLs, reconciliation, boot sequence](phase-01-pki-core.md) | `236b697` |
| 2 | [Listeners, mTLS, deny-list trust, per-request status, live socket eviction](phase-02-listeners-mtls.md) | `7d531f1`, 2.1: `a16ec1d` |
| 3 | [Protocol A enrollment, dev seed tool, simulator enroll and persistence](phase-03-enrollment.md) | `adb62df` |
| 4 | [The thin spine: JWS ingest, replay window, quarantine, serial ledger](phase-04-spine.md) | `0c302cd` |
| 5 | [Operator dashboard: overview API, KMS health monitor, Next.js on the admin port](phase-05-dashboard.md) | `c9645f8` |
| 6 | [WebAuthn admin plane: passkeys, action-bound step-up, KMS-anchored passkey registry](phase-06-webauthn.md) ([manual Touch ID check](phase-06-manual-touchid.md)) | `7c2873d`, 6.1: `309377e` |
| 7 | [Clinical engine: activity context, acute and drift alerts with lineage, compressed clock](phase-07-clinical.md) | `5fc4a79` |
| 8 | [Protocol B renewal: first-use switchover, grace drain, demo TTL rollover](phase-08-renewal.md) | `9b038ea`, 8.1: `dc83baa` |
| 9 | [Recovery: Protocol C re-enrollment, split-brain traps, backstop poller, clock discipline](phase-09-recovery.md) | `f0e511a` |
| 10a | Hardening, no note: no-false-positive gate, demo profile, stage scripts, rehearsal; see [`DEMO_RUNBOOK.md`](../DEMO_RUNBOOK.md), [`demo-fallback.md`](../demo-fallback.md), [`RELEASE_CHECK.md`](../RELEASE_CHECK.md) | `d7272fd`, 10a.1: `ee599b0` |
| 10b | Documents, no note: [spec v2](../vitalsshield_technical_architecture_specification_v2.md), [traceability](../TRACEABILITY.md), [Q&A drill](../QA_DRILL.md) | this phase |
| | [Glossary](GLOSSARY.md) | |

## The finished system on one page

**What it is.** A patient's wearable streams vitals to a server that must be able to say, for every batch: which
device signed it, that the device's certificate was valid at that instant, and that the batch is not a replay. A
clinician must be able to stop a compromised device at once without losing the evidence.

**Keys and certificates.**
- **CAs and KMS:** a two-tier CA (Root, Device Intermediate, plus a Server TLS CA for the gateway) whose private keys
  live only in AWS KMS (LocalStack in development). A fourth KMS key, the registry anchor, signs the stored device and
  passkey registries, so a database edit cannot forge either.
- **Two device keys:** each device has a long-lived device key (DEK) used only to enroll and re-enroll, and a
  short-lived operational leaf key (OLK) for mTLS and for signing telemetry.
- **Lifetimes and the ledger:** leaves last 12 hours in production, 4 minutes in the `local` profile and 3 minutes in
  the `demo` profile. Every serial the CA signs goes through the `issued_serials` ledger, so it is either RECORDED or
  VOIDED and deny-listed.

**Protocols.**
- **A, enrollment:** a clinician approves provisioning with a passkey. The device proves its DEK and a new OLK against
  a single-use bootstrap token.
- **B, renewal:** the device renews itself at two thirds of the leaf's life. The new leaf becomes ACTIVE on its first
  accepted batch, and the old one gets 60 s of grace.
- **C, re-enrollment:** a device whose leaf expired while it was offline re-enrolls with its DEK and keeps its boot
  epoch and sequence numbers.

**Every request.**
- **Revocation in three layers:** the TLS handshake checks an in-memory deny-list, a per-request check reads the
  certificate's status from the database, and a revocation closes every live socket of that certificate within
  milliseconds. A backstop poller re-enforces any revocation within 3 s.
- **Signed batches:** each telemetry batch is a JWS signed by the connection's own certificate key. One SQL statement
  checks it against a 64-bit replay window and stores it; idempotent retries are answered, not stored twice.

**Clinical.**
- Each assignment calibrates a personal resting baseline.
- Drift and acute alerts record exactly which batches and which baseline they came from.
- A passkey-approved quarantine revokes the device, marks the lookback telemetry QUARANTINED, resets tainted
  baselines and retracts only the alerts built on that data. Its audit entry is written in the same transaction.

**Clones.** Three traps (re-enroll collision, sequence regression, use of an old leaf after its grace) treat two
devices acting as one identity as a compromise:
- every certificate is revoked as SUSPECTED_CLONE and the device goes to REAUTH_REQUIRED;
- telemetry is not touched;
- a clinician restores (the real device resyncs to a new epoch) or quarantines.

**Operations.**
- Every timestamp comparison uses the clock that produced the value (`CLOCK_INVENTORY.md`), and a skew monitor
  watches the database clock.
- The admin plane is loopback-only; sessions and ceremonies are in memory.
- The audit log is a hash chain that the database itself keeps append-only.

**Not built (Designed):** CA failover to a standby Intermediate, Redis for multi-gateway eviction and rate limits,
S3 Object Lock anchoring of the audit chain, WebAuthn attestation verification, a Server TLS CA CRL, a durable
clinical outbox, HSM custody and IAM isolation. The residual risks, chief among them a clone that re-enrolls while
the real device is offline, are in spec v2 "Residual risks".

## How the whole system fits together (phase by phase)

VitalsShield is a Spring Boot 4.1 service (module `server`) backed by PostgreSQL 16 and AWS KMS, which is LocalStack
during development. Phase 0 created the Gradle build with three modules (`crypto-common`, `server`, `simulator`), the
Docker Compose stack (Postgres on host port 5433, LocalStack KMS on 4566), the Flyway migration `V1__baseline.sql` that
holds the full spec Section 7 schema plus a `kms_keys` table, and four test tiers (`test`, `integrationTest`, `e2eTest`,
`drillTest`). Phase 1 added the PKI core. On startup, `BootSequence` (an `ApplicationRunner`) runs three steps in
order: `HierarchyReconciler` checks that the four KMS keys recorded in `kms_keys` still exist and are enabled, and in
the `local` profile only rebuilds the whole CA hierarchy (Root CA, Device Issuing Intermediate, Server TLS CA, and a
registry anchor key) if any are missing; `GatewayTlsMaterial` then generates an in-memory P-256 key and gets a gateway
TLS leaf certificate from `KmsCertificateIssuer`; finally `TrustAnchors` loads the current Root and Device
Intermediate. Every CA signature is produced by KMS from a SHA-256 digest through `KmsContentSigner`, so no CA private
key ever exists in the JVM. `CrlService` can produce signed CRLs for the Root and the Device Intermediate as PEM
strings. `crypto-common` holds `CanonicalBytes` and `CanonicalEncodings`, the byte layouts that later phases will sign
and verify. Spring itself never binds a port (`spring.main.web-application-type` is `none`). Phase 2 added
two more boot steps: `CertificateDenyList` loads revoked, expired, and superseded certificates into memory, and then,
always last, `ListenerManager` binds three Reactor Netty servers on 127.0.0.1 that share one Spring `HttpHandler`:
8443 (TLS 1.3, client certificate required), 8444 (TLS 1.3, public: CRLs now, enrollment later), and 8445 (plain HTTP,
admin). `PortEnforcementWebFilter` gives each port its own paths and answers everything else with an empty 404. A
device on 8443 passes three checks: `DynamicMtlsTrustManager` in the handshake (PKIX against the current hierarchy,
leaf policy, deny-list, all in memory), `PostHandshakeGate` after every handshake including resumed ones, and
`CertStatusResolver` on every request (the `certificates` row, read on `boundedElastic`, no cache). Revocation goes
through `SignerRevocationService`: deny-list first, then the database, then `ActiveSessionRegistry` closes the
device's open connections. Phase 2.1 made every TLS session unresumable and cached the CRLs (a GET never signs).
Phase 3 added enrollment (Protocol A) on 8444: a device presents a single-use bootstrap token, its long-lived DEK, a
CSR for a fresh OLK, and a DEK signature binding the three; `EnrollmentService` claims the token in one short
transaction, verifies both proofs and gets two KMS signatures outside any transaction (the DEK registry anchor with Key
#4 and the 12-hour leaf with the Device Intermediate), then activates in a second short transaction that supersedes
any prior certificates (deny-list first, then eviction and CRL republication) and assigns the boot epoch. Until Phase
6, `./gradlew :server:seedDemoDevice` creates the device, assignment, and token in the local database. The
`simulator` module now enrolls, keeps its DEK and OLK in a key and a state partition under `simulator-state/`, skips
re-enrollment while its certificate is valid, and pings `/api/v1/telemetry/ping` over mTLS. Phase 4 closed the spine. The simulator now streams
ES256 JWS batches over a persistent mTLS connection to `POST /api/v1/telemetry/ingest`; the server checks that the TLS
certificate, the JWS `x5t#S256`, and the stored thumbprint agree, verifies with the TLS key only, parses the payload
strictly, classifies it by plausibility and perfusion, and stores it with the spec's single-CTE 64-bit replay window.
`POST /api/v1/admin/devices/{id}/quarantine` (admin port, bearer = the boot setup code) revokes every certificate,
evicts every socket, then under a row lock marks the device QUARANTINED, clears its DEK, revokes its tokens, and runs
the spec's dual-timestamp sanitize with scoped alert retraction. Every device serial is reserved in `issued_serials`
before KMS signs it, so a lost or abandoned leaf is VOIDED onto the CRL and deny-list. Phase 5 added the operator
dashboard, only on the admin port. `GET /api/v1/admin/overview` returns boot steps, KMS key health, the three CA
certificates and the intermediate CRL, live sessions, counters, the serial ledger, recent revocations and quarantines,
and one row per device (serials in OpenSSL's uppercase form); `GET /api/v1/admin/devices/{id}/telemetry` returns a
device's newest rows. Both are read-only. `KmsHealthMonitor` describes the four ACTIVE keys at boot and every 30 s and
reports HEALTHY, UNHEALTHY, or UNKNOWN; it never rebuilds. `DashboardRoutes` serves the Next.js static export from
`dashboard/out` with traversal checks and a CSP that lists the SHA-256 of each inline script instead of allowing
`'unsafe-inline'`. The page signs in with the setup code (kept in sessionStorage), polls the overview every 500 ms,
and its only action is the existing quarantine, which now reports one latency measured from request receipt to every
socket closed. Phase 6 replaced the setup code with passkeys in the default `webauthn` mode. The dashboard runs at
`http://localhost:8445` (the RP id is "localhost"), signs in with Touch ID into an HttpOnly, SameSite=Strict session
cookie, and every non-GET admin request must carry the dashboard's Origin. Each passkey row carries a KMS Key #4
anchor that is checked before every assertion. Provisioning makes the clinician approve the ProvisioningDigest of the
new token, and Protocol A re-verifies that stored approval before any KMS signature, so an SQL-written token cannot
enroll. Quarantine and restore need a fresh approval over a hash of the exact action. Registrations, provisioning,
assignments, quarantines, and restores are written to a hash-chained `security_audit_log`. `vitalsshield.admin.auth=bearer`
keeps the Phase 5 behavior.
Phase 7 added the clinical engine. After each ingest commit, `ClinicalEvaluator` classifies the batch as RESTING or
EXERTION (5 sustained minutes of stillness), raises deduplicated acute and low-perfusion alerts, calibrates a personal
resting baseline from 10 (demo) or 30 trusted resting batches, and raises drift alerts on z-scores against it, each
alert recording its triggering batches and, for drift, its baseline version. Every transaction follows one lock order
(devices, telemetry, assignments, alerts, audit lock last), so a quarantine either sees an evaluation's alert and
retracts it or the evaluation sees the device is no longer ACTIVE. The audit log is append-only by trigger, demo resets
drop the Compose Postgres volume, and the simulator's compressed clock (one batch per second, one minute apart in
measured time) is persisted and drives five switchable scenarios.

Phase 8 added Protocol B renewal. A device with an ACTIVE leaf fetches a stateless HMAC challenge, signs it with its
current key together with a CSR for a new key, and gets a new leaf that stays ISSUED_PENDING_USE until a batch signed
by it is accepted. Then the old leaf becomes RENEWED, keeps working for a 60 s grace window, and is refused at the
handshake with its sockets closed once the grace ends. An unused pending leaf replaced by a later renewal is revoked
as REPLACED_BEFORE_USE and listed on the CRL, every renewal serial goes through the issued_serials ledger, and a
sweeper expires leaves past not_after. The demo leaf is PT4M, so the dashboard shows a rollover every 1m40s. The
clinical queue is capped and its overflow counted, and the SD floors were widened.

Phase 9, the last feature phase, added recovery. A device whose leaf expired while it was offline asks the public port
for a stateless challenge, signs it with its long-lived device key (DEK) and its stored boot_epoch, and gets a new
ACTIVE leaf with the same epoch and sequence numbers (Protocol C); the simulator does this on its own. Three traps
watch for two devices sharing one identity: a re-enrollment while the identity is in use, replayed sequence numbers
from different batches, and an old leaf presented after its grace. Any of them revokes every certificate as
SUSPECTED_CLONE, sets REAUTH_REQUIRED, and raises a pinned security alert without touching telemetry. A clinician then
restores (the real device resyncs to a new epoch) or quarantines. A backstop poller enforces revocations made outside
the process within 3 s, and every timestamp comparison now uses the clock that wrote the value, with the Postgres and
JVM clocks' skew shown on the dashboard.
