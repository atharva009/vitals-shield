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
| | [Glossary](GLOSSARY.md) | |

## How the whole system fits together

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
before KMS signs it, so a lost or abandoned leaf is VOIDED onto the CRL and deny-list.
