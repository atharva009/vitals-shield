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
and verify. The server binds no ports yet: `spring.main.web-application-type` is `none`, and the
`BootSequence` has a marked hook where Phase 2 will bind listeners as the final step. The `simulator` module is still
a stub.
