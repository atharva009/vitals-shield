# VitalsShield: Technical Architecture and System Design Specification (v2, as built)

**How to read this version.** v2 keeps the section numbers and headings of v1
(`docs/vitalsshield_technical_architecture_specification.md`) so the two can be compared side by side. It describes
the system as it stands in the repository, not as it was planned. A bracketed tag marks every passage that changed:
`[D42]` cites row 42 of `docs/DECISIONS.md`; `[code]` marks a correction made to match the code where no DECISIONS row
exists. "Designed" means specified but not built. "Live" means built and running in the hackathon build; Section 8
separates what automated tests exercise from what was only checked by hand.

**Positioning Statement:**

*VitalsShield establishes cryptographic device provenance for wearable telemetry using a CA hierarchy whose signing
keys never leave KMS (the AWS KMS API, served by LocalStack in this build) and per-batch JWS origin authentication,
enforces connection-level and per-request certificate authorization on Reactor Netty with live socket eviction, stops
a detected clone without changing any data, and lets a clinician's passkey-approved quarantine remove a compromised
source's data from each patient's resting baseline and retract the alerts built on it. Degraded readings never enter a
baseline.*
`[D2, D14, D23, D24, D26, D92, code]`

## 1. Key Design Decisions

| Architectural Pillar | Core Mechanism | Engineering Rationale |
| :--- | :--- | :--- |
| **Multi-Port Listener Isolation** | Reactor Netty binds three listeners, last in the boot sequence: Port `8443` (TLS 1.3 only, `ClientAuth.REQUIRE`, every TLS session invalidated after the handshake check so nothing resumes), Port `8444` (TLS 1.3, no client certificate: enrollment, re-enrollment challenge, CRLs), and Port `8445` (plain HTTP admin plane and dashboard). `8443` and `8444` bind `127.0.0.1` by default; `8445` always binds `127.0.0.1` and `::1` and is served as `http://localhost:8445`. There is no load balancer in the build; L4 TCP passthrough in front of the gateways is Designed. `PortEnforcementWebFilter` answers 404 for any path not owned by the receiving port. | Prevents mTLS chicken-and-egg lockouts during enrollment while keeping the raw `io.netty.channel.Channel` of each mTLS connection in the process that decides revocation, so a revoke closes the socket directly. `[D25, D26, D55, code]` |
| **Internal CA Signer Isolation** | **Designed, not built.** In the build the gateway, admin plane, and "signer" code run in one Spring Boot process with one set of KMS credentials and one database user. The `signer` package (`SignerRevocationService`, `BackstopPoller`) and the issuance path (`KmsCertificateIssuer` called by the enrollment, renewal, and re-enrollment services) are in-process Java services; there is no `/internal/v1/signer` RPC. What is live is the proof discipline: every issuance verifies a device-signed proof (DEK proof, OLK renewal proof, DEK re-enrollment proof) and every enrollment re-verifies the clinician's stored WebAuthn approval before any KMS call. | The separate-service split (gateway with zero KMS permissions, signer as sole writer of PKI tables) is the production design. In the build, a compromise of the server process gives `kms:Sign` on every key. `[D8, D57, code]` |
| **First-Use Certificate Activation** | Renewed certificates enter `ISSUED_PENDING_USE` while the prior certificate remains `ACTIVE`, switching over only when a batch signed by the new certificate is accepted. The old certificate becomes `RENEWED` with a grace window (`renewal-grace`, 60 s), is deny-listed from the end of that window, and its live sockets are closed by a scheduled eviction. | Prevents dropped HTTP responses over flaky wireless links from stranding wearables on an expiring drain timer. `[D84, D85]` |
| **Non-Destructive Anomaly Handling** | Three traps (re-enroll collision, sequence regression, post-drain use) trigger one response: every usable certificate of the device is revoked (`SUSPECTED_CLONE`, CRL `keyCompromise`) and its sockets closed, `trust_state` becomes `REAUTH_REQUIRED`, a `SECURITY_ANOMALY_ALERT` and a `SECURITY_ANOMALY` audit entry are written. Telemetry is not changed. | Avoids destroying patient data on a false positive; retroactive data quarantine requires a clinician's passkey step-up approval. `[D91, D92, D93, D94]` |
| **Lineage-Tracked Alert Retraction** | Clinical alerts store `triggering_batch_ids` and (for drift alerts) `baseline_version`; the quarantine statement retracts alerts whose evidence or baseline it quarantines. A clinical streak whose stored batch ids are no longer all trusted starts over. | Prevents compromised sensor batches from corrupting locked reference baselines or leaving stale alerts in the clinician queue. `[D78]` |
| **Passkey Admin Plane** (new row) | Clinicians sign in with WebAuthn passkeys (Yubico `java-webauthn-server` 2.10.1, RP ID `localhost`, user verification required, attestation `none`). Sessions are a random 32-byte id in an HttpOnly, SameSite=Strict cookie, held in memory (30 min idle, 8 h absolute), and every non-GET admin request must carry an allowed `Origin`. The boot setup code only registers the first clinician passkey. A signature counter of 0 is always accepted; a non-zero counter must increase. | Ties provisioning, quarantine, and restore to a person holding a passkey, and keeps a file-based secret from becoming a standing admin password. `[D54, D55, D59, D60, D61, D63, D64, D66]` |

Real Touch ID was verified by hand once (2026-11-16, MacBook, Chrome): registration with the setup code, a Touch ID
provisioning approval that passed Protocol A re-verification, and a Touch ID step-up quarantine. Every automated test
uses a software authenticator. `[D80]`

## 2. Security Boundaries and Threat Model

| Security Layer | Mechanism | What It Proves | Explicit Limitation and Residual Risk |
| :--- | :--- | :--- | :--- |
| **1. Transport Authentication** | Mutual TLS 1.3 on Reactor Netty (Port `8443`). The JDK session-ticket extension is disabled and `PostHandshakeGate` invalidates every server session after its deny-list check, so no connection resumes. `DynamicMtlsTrustManager` validates `chain[0]` against the current Device Intermediate and Root (PKIX, revocation checking off), enforces `CA:FALSE`, `digitalSignature`, EKU `clientAuth`, and AKI equal to the current Device Intermediate SKI, then checks the in-memory deny-list. | Every TCP connection is a full TLS 1.3 handshake, so the peer proves possession of the private key for the presented operational leaf (CertificateVerify) on every connection, and the trust manager runs on every connection. | Revocation on an open keep-alive connection depends on the uncached per-request check and on socket eviction (Section 4). The server sends TLS alert 46 (`certificate_unknown`) for every rejected client certificate, including revoked and expired ones: JDK 21 maps the server-side check to 46 regardless of the `CertPathValidatorException` reason the trust manager attaches, so a client cannot tell revoked from unknown. `[D26, D37]` |
| **2. Origin Authentication and At-Rest Integrity** | RFC 7515 JWS (`ES256`) with `x5t#S256` binding. Header allow-list: `alg` = `ES256`, `typ` = `vitalsshield.telemetry+jws`, `x5t#S256` required; `jwk`, `jku`, `x5c`, `x5u`, and `crit` rejected. The verification key comes only from the TLS client certificate of the connection. | The telemetry batch was signed by the operational leaf key of the authenticated TLS client certificate (TLS leaf thumbprint = stored `cert_thumbprint_s256` = header `x5t#S256`), its `device_id` is that certificate's device, and the stored compact JWS remains verifiable at rest. | Provides cryptographic **origin authentication** only; if wearable firmware is rooted, the attacker can sign falsified sensor values. `[D35, D43]` |
| **3. Provisioning and Registry Integrity** | KMS-anchored clinician passkey -> provisioning assertion -> KMS Key #4 DEK anchor. Key #4 signs `PasskeyAnchorBytes` on passkey registration and `DekAnchorBytes` on enrollment; the passkey anchor is verified before every assertion, and Protocol A re-verifies the stored provisioning assertion before any KMS signature. The DEK anchor is re-verified on every re-enrollment. | A row inserted or edited by SQL alone cannot create a working clinician passkey, a bootstrap token that enrolls, or a DEK that re-enrolls (`clinician_passkeys`, `device_bootstrap_tokens.webauthn_*`, `devices.dek_spki_der_b64`) without a Key #4 signature or a real passkey assertion. | In the build every component runs in one process holding KMS credentials for all four keys; a compromise of that process can call `kms:Sign` on any of them. The CloudWatch alarms and IAM session revocation that bound this in production are Designed. The dev seed passkey is a software key in a file; it is restricted to the seed tool's own provisioning in the `local` profile. `[D3, D7, D56, D57, D66, code]` |
| **4. Device Credential Hierarchy** | Long-lived DEK (Protocol C re-enrollment) + short-lived OLK (mTLS and JWS). Production leaf `PT12H`; renewal due at 2/3 of validity (8 h for `PT12H`). The `local` profile uses `PT4M` and the `demo` profile `PT3M` (notBefore is backdated 60 s). Every renewal and re-enrollment re-checks `trust_state = 'ACTIVE'`, the active assignment, and `max_renewal_horizon` (30 days by default). | Limits active transport key exposure to one leaf lifetime plus grace, and enforces periodic authorization checks against `max_renewal_horizon`. | Without a hardware secure element (for example, ATECC608), the DEK is a software key (the simulator keeps it in `keys/dek.key`, mode 600); extracting it allows re-enrollment while the legitimate device is idle or offline until `max_renewal_horizon` expires or a clinician quarantines the device. `[D83, D99]` |
| **5. Split-Brain Anomaly Detection** | Three traps: the re-enroll collision (a usable certificate that is in use right now), the sequence-regression trap (3 or more replay-type rejections with distinct `batch_id`s within 60 s), and the post-drain trap (a `RENEWED` certificate presented more than 5 s after its grace ended while its successor is `ACTIVE`). Each raises the non-destructive anomaly response. | Detects concurrent use of one device identity from two copies of its keys and moves the device to `REAUTH_REQUIRED` with every usable certificate revoked; normal behavior (rollovers, offline expiry recovery, idempotent retries) raises no anomaly. | If the legitimate device is off or offline when a clone re-enrolls with a copied DEK, the takeover looks like a normal offline recovery until the legitimate device reconnects. A clone copied shortly before a scheduled renewal can win the renewal race; the real device then sees what looks like a lost renewal response. Two copies that never overlap look like one device. The thresholds (3 in 60 s, 5 s after grace) were chosen for the demo, not measured against real gateway reordering. `[D91, D93, D94, D100, D102]` |
| **6. Replay and Ordering Defense** | Single-CTE atomic 64-bit sliding bitmap on `devices`, with `telemetry_records` unique on `(device_id, boot_epoch, sequence_number)`; sequence numbers start at 1. | Accepts each sequence number at most once per boot epoch, accepts out-of-order arrival within 63 positions of the highest sequence seen, and tells an idempotent retry (same `batch_id`, same payload hash, same epoch) from a replay. | Wearables must drain buffered offline frames in FIFO order before transmitting live measurements, and `transmitted_at` must be within 5 minutes of server time. The build runs one gateway process, so the window has not been exercised against real multi-gateway reordering. `[D40, code]` |

### 2.1 Claims by layer (as built)

Each claim below is one sentence that the traceability matrix maps to tests or manual evidence. `[code]`

**Layer 1, transport authentication**

- L1.1 Port 8443 accepts only TLS 1.3 and requires a client certificate.
- L1.2 No TLS session on port 8443 resumes: every connection is a full handshake in which the trust manager runs and the client signs CertificateVerify with its leaf key. `[D26]`
- L1.3 The trust manager uses only the first certificate the client sends, validates it against the current Device Intermediate and Root, and ignores any intermediate the client supplies.
- L1.4 A leaf that is a CA, lacks `digitalSignature`, lacks EKU `clientAuth`, or whose AKI is not the current Device Intermediate SKI is rejected at the handshake.
- L1.5 A leaf issued under a previous (rebuilt) hierarchy is rejected at the handshake even though it carries the same issuer DN.
- L1.6 A deny-listed certificate is rejected at the handshake with no database access on the event loop. `[D24]`
- L1.7 The post-handshake gate re-checks the deny-list after every completed handshake and closes a deny-listed session. `[D24]`
- L1.8 A certificate whose database status changes is refused on the next request on the same open connection, because the per-request status check has no cache. `[D23]`
- L1.9 Revoking a certificate closes its live mTLS sockets; the measured revoke-to-close latency is under 500 ms. `[D11]`
- L1.10 A rejected client certificate receives TLS alert 46 (`certificate_unknown`). `[D37]`

**Layer 2, origin authentication**

- L2.1 A batch is accepted only if its JWS verifies with the public key of the TLS client certificate of the connection that carried it.
- L2.2 The JWS header must be exactly `alg` ES256, `typ` `vitalsshield.telemetry+jws`, and `x5t#S256` equal to the TLS leaf thumbprint; `jwk`, `jku`, `x5c`, `x5u`, and `crit` are rejected. `[D43]`
- L2.3 A payload whose `device_id` is not the TLS certificate's device is rejected with 403 `DEVICE_MISMATCH`.
- L2.4 Unknown, missing, or null payload fields are rejected. `[D43]`
- L2.5 The compact JWS is stored with each batch, so its origin can be re-verified at rest.

**Layer 3, provisioning and registry integrity**

- L3.1 Every clinician passkey row carries a KMS Key #4 signature over `PasskeyAnchorBytes`, verified before every assertion against that credential. `[D56]`
- L3.2 Protocol A re-verifies the clinician's stored provisioning assertion (signature, challenge equal to the recomputed `ProvisioningDigest`, RP ID hash, UP and UV flags, origin) before any KMS signature; a token row without a valid assertion cannot enroll. `[D57]`
- L3.3 Enrollment stores a KMS Key #4 signature over `DekAnchorBytes`, and re-enrollment re-verifies it; an SQL edit of the DEK yields 403 `DEVICE_NOT_ENROLLABLE`.
- L3.4 Quarantine and restore-active each need a fresh passkey assertion whose challenge is SHA-256 of a canonical encoding of the action and its server-held parameters. `[D58]`
- L3.5 After the first clinician passkey exists, the setup code authorizes nothing. `[D60]`
- L3.6 The dev seed passkey cannot sign in or approve any step-up, and outside the `local` and `demo` profiles every assertion it makes is refused. `[D66, D99]`

**Layer 4, device credential hierarchy**

- L4.1 A device renews its leaf at 2/3 of the leaf's validity without human action, proving possession of the current OLK and of the new key. `[D83]`
- L4.2 Renewal is refused for a device that is not `ACTIVE`, has no active assignment, or is past `max_renewal_horizon`; re-enrollment is refused for a device that is not `ACTIVE` or is past `max_renewal_horizon`. (Re-enrollment without an active assignment is refused by the same code path, `409 DEVICE_UNASSIGNED`, but no test exercises it.)
- L4.3 A device whose leaf expired while offline recovers with its DEK through Protocol C, keeping its boot epoch and sequence window. `[D95, D97]`
- L4.4 An expired leaf without the DEK cannot re-enroll.

**Layer 5, split-brain anomaly detection**

- L5.1 A re-enrollment while the device has a usable certificate that has a live socket or an ingest within 30 s raises `REENROLL_COLLISION`. `[D91]`
- L5.2 An expired certificate alone never counts as a collision. `[D91]`
- L5.3 Three or more `DUPLICATE_SEQUENCE_REPLAY`, `SEQUENCE_TOO_OLD`, or `BOOT_EPOCH_MISMATCH` rejections with distinct `batch_id`s within 60 s raise `SEQUENCE_REGRESSION`; idempotent retries never count. `[D93]`
- L5.4 Presenting a `RENEWED` certificate more than 5 s after its grace ended, while its successor is `ACTIVE`, raises `POST_DRAIN_USE`. `[D94]`
- L5.5 A re-enrollment presenting a boot epoch above the stored one raises `BOOT_EPOCH_INVALID`; one below it without a clinician restore raises `BOOT_EPOCH_REGRESSION`.
- L5.6 The anomaly response revokes every usable certificate of the device (`SUSPECTED_CLONE`), closes its sockets, sets `REAUTH_REQUIRED`, writes a `SECURITY_ANOMALY_ALERT` and a `SECURITY_ANOMALY` audit entry, and changes no telemetry. `[D92]`
- L5.7 Normal operation (rollovers, offline expiry recovery, idempotent retries) with all traps enabled raises no anomaly. `[D100]`

**Layer 6, replay and ordering**

- L6.1 Each `(device_id, boot_epoch, sequence_number)` is accepted at most once.
- L6.2 A sequence number up to 63 below the highest seen is accepted once if its bit is clear; a sequence number more than 63 below the highest seen is rejected as `SEQUENCE_TOO_OLD`.
- L6.3 Concurrent duplicates of one frame produce exactly one stored row and no transaction abort.
- L6.4 A retry with the same `batch_id`, payload hash, and boot epoch returns 200 with `idempotent_retry: true`.
- L6.5 A `batch_id` reused with a different payload or sequence number is rejected with 409 `BATCH_ID_REUSED`. `[code]`
- L6.6 Sequence numbers below 1 are rejected. `[D40]`

## 3. Two-Tier AWS KMS PKI, Signer Isolation, and RFC 5280 Profiles

### Key Custody, DB Role Separation, and Signer Isolation

**As built.** Four non-exportable `ECC_NIST_P256` / `SIGN_VERIFY` keys live in KMS (LocalStack): Key #1 Root CA, Key #2
Device Issuing Intermediate, a Server TLS CA key (an addition, not v1's Key #3), and Key #4 Registry and Audit Anchor.
The `kms_keys` table records each key by purpose (`ROOT_CA`, `DEVICE_INTERMEDIATE`, `SERVER_TLS_CA`,
`REGISTRY_ANCHOR`), at most one `ACTIVE` per purpose. Signing uses `MessageType DIGEST` with `ECDSA_SHA_256`: the
server hashes the to-be-signed bytes and sends the 32-byte digest, because `RAW` caps messages at 4096 bytes, which a
CRL passes at about 100 entries. KMS returns DER ECDSA signatures; signatures outside JWS (DEK proofs, KMS anchors) stay
DER, and only JWS uses raw `R||S`. The certificate issuer sits behind a `CertificateIssuer` interface with one
implementation, `KmsCertificateIssuer`; a Keytos EZCA implementation of that interface is Designed.
`[D2, D14, D17, D33, code]`

The Server TLS Issuing CA (EKU `serverAuth`, under the Root) issues the gateway's TLS leaf for ports 8443 and 8444. The
gateway's private key is the one key outside KMS: an EC P-256 key generated in JVM memory at each boot, never written
to disk, with a 24 h leaf. Its leaf carries `IP:127.0.0.1` and `DNS:localhost` SANs, and the simulator connects to
`127.0.0.1` with hostname verification on. The simulator trusts the Root (`var/trust/root-ca.pem`); the Device
Intermediate stays `clientAuth`-only. `[D2, D15, D36]`

Everything runs in one Spring Boot process with one database user (`vitalsshield`) and one set of KMS credentials:

```text
+----------------------------------------------------------------------------+
|  ONE SPRING BOOT PROCESS (hackathon build)                                 |
|                                                                            |
|  Port 8445, plain HTTP, 127.0.0.1 and ::1 (admin API + dashboard)          |
|    WebAuthn passkeys, sessions, step-up, provisioning, audit log           |
|                                                                            |
|  Port 8444, TLS 1.3 (enroll, challenge, re-enroll, CRLs)                   |
|  Port 8443, TLS 1.3 mTLS (telemetry, renew-challenge, renew)               |
|    DynamicMtlsTrustManager, PostHandshakeGate, CertStatusResolver,         |
|    ActiveSessionRegistry                                                   |
|                                                                            |
|  In-process services: EnrollmentService, RenewalService, ReEnrollService,  |
|    CertificateActivationService, SignerRevocationService, AnomalyService,  |
|    QuarantineService, CrlService, BackstopPoller, KmsCertificateIssuer     |
|                                                                            |
|  KMS client (all four keys)        JDBC (one user, all tables)             |
+-------------------+--------------------------------+-----------------------+
                    |                                |
                    v                                v
          LocalStack KMS (Docker)           PostgreSQL (Docker)
```

`[D8, code]`

**Designed (production).** v1's split remains the production design and is not built: an offline Root ceremony role
(`VitalsShieldRootCaCeremonyRole`, hardware MFA); an admin plane on internal DNS with `vitalsshield_admin_role`; an
internal CA Signer Service in a private subnet with `VitalsShieldCaSignerRole` and `vitalsshield_signer_role`, holding
Key #2, the Cold Standby Intermediate Key #3, and Key #4 as multi-region `mrk-*` keys, and being the sole writer to
`certificates`, `device_bootstrap_tokens`, `clinician_passkeys`, and the `devices.dek_*` / `trust_state` columns; and
a DMZ gateway with `VitalsShieldGatewayRole` (zero KMS permissions) and `vitalsshield_gateway_role` (SELECT on PKI
tables; writes only to telemetry, alerts, and replay counters), talking to the Signer over internal mTLS RPC. None of
these IAM roles, database roles, the standby key, or the replica keys exist in the build (`ca_issuers.kms_replica_arn`
is always NULL; the `STANDBY` value of `ca_status` is unused). `[code]`

**Local KMS Profile (LocalStack):** For local development and the hackathon demo, `KmsClient` accepts an endpoint
override (`vitalsshield.kms.endpoint=http://localhost:4566`) with an explicit region (`us-east-1`) and placeholder
credentials (`test` / `test`), targeting LocalStack in Docker Compose. The container reads `LOCALSTACK_AUTH_TOKEN` from
a gitignored `.env` file. LocalStack reproduces the KMS API (`ECC_NIST_P256`, `ECDSA_SHA_256`) but not HSM key custody
or IAM isolation, and a LocalStack restart deletes every key. At boot, `HierarchyReconciler` reads the `ACTIVE` rows of
`kms_keys` (not the key IDs in `ca_issuers`, because Key #4 has no `ca_issuers` row) and calls `DescribeKey` on each. A
key counts as lost only on `NotFoundException` or a state other than `Enabled`; a network or authorization error
propagates and fails startup, so a KMS outage is never mistaken for key loss. With `allow-hierarchy-rebuild=true` (the
`local` and `demo` profiles only), a lost key triggers an all-or-nothing rebuild: four new keys are created, the Root,
Device Intermediate, and Server TLS CA certificates are signed, and one transaction (under an advisory lock, re-checking
the `ACTIVE` key set) retires the old `kms_keys` rows, marks the old `ca_issuers` rows `REVOKED` (never deleted), revokes
every non-revoked leaf with `HIERARCHY_REBUILD`, clears every device's DEK anchor, and resets `trust_state` to
`PROVISIONED` except for `QUARANTINED` and `DECOMMISSIONED` devices. The trust file is rewritten by atomic rename after
commit. Because DEK anchors are cleared, every device must be re-provisioned through Protocol A after a rebuild. Keys
created by a failed rebuild are scheduled for deletion. Outside those profiles a missing key fails startup closed and no
key is created. `[D12, D14, D20]`

**KMS health monitor.** After reconciliation and every 30 s, `KmsHealthMonitor` calls `DescribeKey` on the four
`ACTIVE` keys and reports the result on the dashboard. It never rebuilds at runtime; recovering from a lost key means
restarting the server, which rebuilds and revokes every device. `[D49]`

**Boot order.** Flyway migrates during context refresh. `BootSequence` then runs these steps on the boot thread, each
publishing a `BootStepCompleted` event shown at `GET /api/v1/admin/boot-status`: `[D16, D38, D87, D98]`

1. `RECONCILED`: hierarchy reconciliation as above. Right after it, the first KMS health check runs and the 30 s
   monitor starts, and `ClockSkewMonitor` takes its first measurement of Postgres `clock_timestamp()` against the JVM
   clock and starts its 60 s schedule. The skew check reports; it does not stop the boot. `[D49, D98]`
2. `SERIALS_SWEPT`: serials `RESERVED` for more than 2 minutes (a crash after signing) are marked `VOIDED`, so the
   deny-list seed and the first CRL include them. `[D38]`
3. `GATEWAY_TLS_ISSUED`: the in-memory gateway key and its 24 h leaf from the current Server TLS CA. `[D15]`
4. `TRUST_ANCHORS_LOADED`: the current Root and Device Intermediate, read from `ca_issuers`.
5. `DENY_LIST_SEEDED`: revoked, expired, renewed, and voided serials are loaded into the in-memory deny-list, the 30 s
   union refresh starts, and the boot expiry sweep marks every `ACTIVE`, `ISSUED_PENDING_USE`, or `RENEWED` certificate
   past `not_after` as `EXPIRED` and deny-lists it, so a certificate that expired while the server was down is refused
   before any port opens. `[D28, D87]`
6. `CRLS_PUBLISHED`: both CRLs are signed and cached, and the 10-minute `nextUpdate` watch starts. `[D27]`
7. `ADMIN_CODE_ISSUED`: a new random setup code is written to `var/admin/setup-code` (mode 600); only its path is
   logged. `[D41]`
8. `LISTENERS_BOUND`: always last; ports 8443, 8444, and 8445 open only after every earlier step completed. The
   backstop poller, the renewal sweepers, and the post-drain trap's drain loop start on this event. `[D84, D94, D96]`

### Canonical Binary Encodings

All multi-field cryptographic signatures use explicit big-endian length prefixes (`uint32_be`) or fixed-width digests
so fields cannot be shifted across boundaries. The layouts are implemented once in `crypto-common`
(`CanonicalEncodings`) and checked against an independent Python implementation (`scripts/golden_vectors.py`).
`[code]`

1. **Clinician Passkey Anchor (`passkey_registry_kms_sig`, signed by KMS Key #4):**
   `PasskeyAnchorBytes = uint32_be(len(cred_id)) || utf8(cred_id) || uint32_be(len(clinician_id)) || utf8(clinician_id) || sha256(cose_pub_key_der)`
   (live: signed on every passkey registration and verified before every assertion) `[D56]`

2. **Clinician WebAuthn Provisioning Commitment (`ProvisioningDigest`):**
   `ProvisioningDigest = SHA256(uint32_be(len(device_id)) || utf8(device_id) || sha256(bootstrap_token_ascii) || int64_be(expires_at_epoch_ms))`
   The 32-byte digest is the WebAuthn challenge of the provisioning ceremony; `expires_at` is the token expiry (issue
   time + 15 minutes, JVM clock). `[D10, D89]`

3. **Enrollment DEK Proof-of-Possession (`dek_proof_sig`, signed by Device `DEK`):**
   `DekEnrollmentProofBytes = uint32_be(len(device_id)) || utf8(device_id) || sha256(bootstrap_token_ascii) || sha256(olk_csr_der)`

4. **DEK Registry Anchor (`dek_registry_kms_sig`, signed by KMS Key #4):**
   `DekAnchorBytes = uint32_be(len(device_id)) || utf8(device_id) || sha256(dek_spki_der) || int64_be(provisioned_at_epoch_ms)`
   (`dek_spki_der` is stored base64 in `devices.dek_spki_der_b64`) `[D7]`

5. **OLK Renewal Proof (`olk_renewal_sig`, signed by Current `OLK`):**
   `OlkRenewalProofBytes = uint32_be(len(issuer_key_hash)) || utf8(issuer_key_hash) || uint32_be(len(serial_number)) || utf8(serial_number) || int64_be(issued_at_ms) || random_nonce (16B) || sha256(olk_new_csr_der)`

6. **DEK Re-Enrollment Proof (`dek_sig`, Protocol C, signed by Device `DEK`):** (moved here from Section 4)
   `ReEnrollProofBytes = uint32_be(len(device_id)) || utf8(device_id) || int64_be(issued_at_ms) || random_nonce (16B) || int64_be(boot_epoch) || sha256(olk_csr_der)`
   The nonce carries no length prefix, so it is fixed at 16 bytes. `[D21]`

7. **Step-up approval digests (new):** the WebAuthn challenge for quarantine is
   `SHA256(utf8WithLength("vitalsshield.quarantine.v1") || utf8WithLength(device_id) || uint32_be(lookback_minutes) || utf8WithLength(reason) || nonce (16B))`,
   and for restore-active `SHA256(utf8WithLength("vitalsshield.restore-active.v1") || utf8WithLength(device_id) || nonce (16B))`,
   where `utf8WithLength(s) = uint32_be(len(s)) || utf8(s)` and the nonce is server-generated. `[D58]`

### Explicit RFC 5280 X.509v3 Certificate Profiles

Issuance ignores all Subject, SAN, and extension attributes inside the client's PKCS#10 CSR, using the CSR solely to
extract the candidate `SubjectPublicKeyInfo` and verify its proof-of-possession signature. Serials are random, at most
20 octets, stored as lowercase hex and displayed as uppercase whole-byte hex (the `openssl` format). The Server TLS CA
and gateway leaf profiles are additions. `[D2, D50, code]`

| Field / Extension | Root CA Profile | Device Issuing Intermediate CA Profile | Server TLS CA Profile (new) | Wearable Operational Leaf Profile |
| :--- | :--- | :--- | :--- | :--- |
| **Signature Algorithm** | `SHA256withECDSA` (KMS Key #1) | `SHA256withECDSA` (signed by KMS Key #1) | `SHA256withECDSA` (signed by KMS Key #1) | `SHA256withECDSA` (signed by KMS Key #2, single-region in the build) |
| **Subject DN** | `CN=VitalsShield Root CA, O=VitalsShield` | `CN=VitalsShield Issuing CA G1, O=VitalsShield` | `CN=VitalsShield Server TLS CA G1, O=VitalsShield` | `CN=<device_id>, O=VitalsShield Devices` |
| **Validity Period** | 10 Years | 1 Year | 1 Year | `leaf-ttl`: **`PT12H`** by default, `PT4M` in `local`, `PT3M` in `demo`; notBefore = issuance - 60 s; renewal due at 2/3 of `[not_before, not_after)` |
| **Basic Constraints** | `critical, CA:TRUE, pathLenConstraint:1` | `critical, CA:TRUE, pathLenConstraint:0` | `critical, CA:TRUE, pathLenConstraint:0` | `critical, CA:FALSE` |
| **Key Usage (`KU`)** | `critical, keyCertSign, cRLSign` | `critical, keyCertSign, cRLSign` | `critical, keyCertSign, cRLSign` | `critical, digitalSignature` |
| **Extended Key Usage (`EKU`)** | *Omitted* | `id-kp-clientAuth` (non-critical) | `id-kp-serverAuth` (non-critical) | `critical, id-kp-clientAuth` (`1.3.6.1.5.5.7.3.2`), enforced by `DynamicMtlsTrustManager` |
| **Subject Key Identifier (`SKI`)** | SHA-256 of Root SPKI DER | SHA-256 of Intermediate SPKI DER | SHA-256 of CA SPKI DER | SHA-256 of Leaf SPKI DER |
| **Authority Key Identifier (`AKI`)** | *Omitted on self-signed root* | Root `SKI` (`issuer_key_hash`) | Root `SKI` | Intermediate `SKI` (`issuer_key_hash`); the trust manager requires it to equal the current Device Intermediate SKI |
| **Subject Alternative Name (`SAN`)** | *Omitted* | *Omitted* | *Omitted* | **Non-critical** (per RFC 5280 §4.2.1.6), `URI:urn:vitalsshield:device:<device_id>` |
| **CRL Distribution Points** | *Omitted on self-signed root* | `https://localhost:8444/api/v1/pki/root-crl.pem` (`vitalsshield.pki.public-base-url`) | same Root CRL URL | `https://localhost:8444/api/v1/pki/intermediate-crl.pem` (`nextUpdate` = 24 h) |

SKIs use RFC 7093 §2 method 4 (SHA-256 of the SPKI DER, full 32 bytes); `issuer_key_hash` is its lowercase hex. The
Device Intermediate's `clientAuth` EKU is informational: the gateway enforces EKU on the leaf, and the AKI rule pins the
leaf to the current Device Intermediate. The gateway leaf (`CN=VitalsShield Gateway`, 24 h, `CA:FALSE`,
`digitalSignature`, EKU `serverAuth`, SANs `IP:127.0.0.1` and `DNS:localhost`) is signed by the Server TLS CA. Gateway
leaves are not recorded in `issued_serials`, and the Server TLS CA publishes no CRL; a Server TLS CA CRL is Designed.
App revocation reasons map to RFC 5280 `CRLReason` (`KEY_COMPROMISE` and `SUSPECTED_CLONE` to `keyCompromise`;
`REPLACED_BEFORE_USE`, `SUPERSEDED_BY_REPROVISION`, `SUPERSEDED_BY_REENROLL`, and voided serials to `superseded`;
`HIERARCHY_REBUILD` to `cessationOfOperation`; `CA_COMPROMISE` to `cACompromise`);
`unspecified` omits the reason extension. `[D18, D19, D36, D39, D83, D99, code]`

## 4. Enrollment, First-Use Renewal, and Split-Brain Recovery

### Wearable Persistence and Reboot Semantics

Wearables persist their active `OLK` keypair, operational X.509 certificate, `boot_epoch`, and `sequence_number` in
non-volatile flash across normal power cycles. Consequently, a routine reboot reconnects directly over Port `8443` mTLS
using its existing certificate and continuing `sequence_number` without triggering `/re-enroll` or false-positive clone
alerts. `/re-enroll` on Port `8444` is invoked when the operational certificate expires while offline, or after a reset
of the device's state partition (after a clinician restore). Intermediate CA failover, the third trigger in v1, is
Designed. A `local`-profile hierarchy rebuild clears every DEK anchor, so after a rebuild devices are re-provisioned
through Protocol A, not Protocol C. The DEK is stored in a separate key partition that survives a state reset, so a
device that loses only its `boot_epoch` and `sequence_number` can still prove its identity and recover through
clinician `restore-active` plus `/re-enroll`. A full factory wipe that erases the DEK cannot re-enroll; the clinician
must re-provision the device through Protocol A with a new bootstrap token, which replaces the stored DEK and its
`dek_registry_kms_sig`. `[D12, D20, code]`

**The simulator as built.** The simulator (`simulator/`) keeps its DEK in `keys/` and its OLK, certificate, epoch,
sequence, assignment id, and last `measured_at` in `state/` (files mode 600, atomic renames). A renewed certificate and
its key are written as `olk-pending.*` before use and promoted to current after the first 200; on restart a valid
pending pair is preferred. It retries the same frame (same `batch_id` and sequence number) until it succeeds, instead
of keeping a flash ring buffer. It runs Protocol C on its own when its leaf has expired (a 403 with reason `EXPIRED` or
`OUTSIDE_VALIDITY`, a refused handshake while its certificate is past `not_after`, or an expired certificate with no
valid pending one at launch), and resends the refused frame with the new key. Exit codes: 3 when its certificate is
revoked (no recovery attempt), 5 on `REAUTH_REQUIRED` or any epoch rejection. `[D44, D85, D95]`

### Certificate Lifecycle State Machine (First-Use Switchover)

Acceptance is enforced in two places with different data, so neither needs the other to be current: `[D23, D24, D84,
D87]`

- **Handshake (`DynamicMtlsTrustManager`, Netty event loop, no I/O):** PKIX validity and chain to the current Device
  Intermediate, leaf policy, then the in-memory deny-list. The deny-list holds `REVOKED` and `EXPIRED` certificates,
  `VOIDED` serials, and `RENEWED` certificates from their `grace_expires_at` (each entry has a `deniedFrom` instant
  compared with the JVM clock). A certificate the CA signed but the database does not know passes the handshake and is
  stopped per request. An allow-list would refuse a certificate issued a millisecond earlier; a deny-list does not.
- **Per request (`CertStatusResolver`, every request on 8443):** a primary-key read of `certificates` on
  `boundedElastic`, no cache. Accepted: `ACTIVE` or `ISSUED_PENDING_USE`, or `RENEWED` while JVM now <
  `grace_expires_at`; in every case JVM now must be within `[not_before, not_after)`. Otherwise 403
  `CERT_NOT_ACCEPTED` with reason `UNKNOWN`, `REVOKED`, `EXPIRED`, `SUPERSEDED`, or `OUTSIDE_VALIDITY`.

```text
                      [POST /api/v1/devices/renew]
                                   |
                                   v
                        ISSUED_PENDING_USE
        (Accepted per request; old cert remains ACTIVE, so a lost
         response leads to another renewal, which revokes this one
         as REPLACED_BEFORE_USE)
                                   |
        First accepted telemetry batch signed by the new cert
                                   |
                                   v
                                ACTIVE
        (Old cert transitions to RENEWED with grace_expires_at =
         JVM now + renewal-grace (60 s), deny-listed from that
         instant; its sockets are closed when the grace ends)
                                   |
        +--------------------------+--------------------------+
        |                          |                          |
        v                          v                          v
     RENEWED                    REVOKED                    EXPIRED
 (Valid until               (Terminal: deny-listed     (Set by the expiry sweep
  grace_expires_at,          before commit, sockets     when JVM now >= not_after,
  then SUPERSEDED)           closed via Netty)          for ACTIVE, PENDING, RENEWED)
```

`[D84, D87, D89]`

The expiry sweep runs every 30 s and once at boot inside `DENY_LIST_SEEDED`. It covers `ACTIVE`,
`ISSUED_PENDING_USE`, and `RENEWED` certificates past `not_after`, compared with the JVM clock, one transaction per
certificate (devices row, then certificate row): the certificate is deny-listed (`deniedFrom` = `not_after`) before
commit, marked `EXPIRED`, and its live sockets are evicted. The dashboard flags `CERT_EXPIRED_NO_SUCCESSOR`. `[D84,
D87]`

### Protocol A: WebAuthn-Anchored Bootstrap Enrollment (Port `8444`, `POST /api/v1/devices/enroll`)

**Provisioning (admin plane, before Protocol A).** A clinician with a passkey session calls
`POST /api/v1/admin/devices/provision/begin` (device id, patient id, birth year, `max_renewal_days`, default 30). The
server generates the bootstrap token and returns a WebAuthn request whose challenge is the `ProvisioningDigest` of the
device id, the token, and its expiry (15 minutes). `provision/finish` takes only the assertion; on success one
transaction inserts the device row if it does not exist, creates the `ACTIVE` assignment (`ASSIGNMENT_CREATED`), stores the token
hash with the exact signed WebAuthn bytes (base64url) in `device_bootstrap_tokens.webauthn_*`, and appends
`DEVICE_PROVISIONED`. The plaintext token is shown once and is never stored. Provisioning ceremonies are keyed by a
random `ceremony_id` with a 2-minute TTL; any unknown, used, or expired ceremony is 410 `CEREMONY_EXPIRED`.
`[D4, D10, D65]`

1. Wearable submits `{device_id, bootstrap_token, dek_spki_der_b64, olk_csr_der_b64, dek_proof_sig}` to Port `8444`,
   handled in-process by `EnrollmentService`. The simulator connects to `https://127.0.0.1:8444` with hostname
   verification on (the gateway leaf has an IP SAN). `[D36, code]`

2. **Short Tx 1:** locks the `device_bootstrap_tokens` row and moves it `ISSUED` -> `CLAIMING` (a `CLAIMING` token
   older than 2 minutes, by Postgres time, can be claimed again), checks the device and its `ACTIVE` assignment, and
   reserves the leaf serial in `issued_serials` (`RESERVED`) before any KMS call. A stale reclaim also sweeps stale
   reservations. `[D34, D38]`

3. **Out-of-Tx Verification and KMS Signing:**

   * Verifies `passkey_registry_kms_sig` (KMS Key #4 public key), then re-verifies the stored WebAuthn assertion from
     the token row alone, without ceremony state: signature, challenge equal to the recomputed `ProvisioningDigest`,
     RP ID hash, UP and UV flags, and origin. A failure is 403 `PROVISIONING_UNVERIFIED`; the reserved serial is voided
     without republishing the CRL (it was never signed, so no KMS Sign is spent; it joins the next CRL). A token
     approved by the dev seed passkey passes only in the `local` and `demo` profiles. `[D57, D65, D66, D99]`

   * Verifies `dek_proof_sig` (DER ECDSA) over `DekEnrollmentProofBytes` and the `OLK` CSR signature. `[D33]`

   * Calls `kms:Sign` on KMS Key #4 to produce `dek_registry_kms_sig` over `DekAnchorBytes`, and on KMS Key #2 to sign
     the leaf (`leaf-ttl`). Both anchors and the re-verification are live, not Designed. `[D3]`

4. **Short Tx 2:** deny-lists and revokes any prior certificates for `device_id` (`SUPERSEDED_BY_REPROVISION`),
   persists the `dek_*` columns on `devices` (`trust_state = 'ACTIVE'`), inserts the `ACTIVE` certificate (with
   `cert_thumbprint_s256` = base64url(SHA-256(cert DER)), the JWS `x5t#S256` value), marks the serial `RECORDED`, and
   marks the token `CONSUMED`. A first-time device (no prior `certificates` row) keeps `boot_epoch = 1`; any other
   device receives `boot_epoch = devices.boot_epoch + 1` with `last_sequence_num = 0` and `replay_bitmap = 0`, so new
   batches never collide with historical sequence numbers. `provisioned_at` cannot decide this, because a rebuild
   resets it. After commit, old sockets are evicted and the CRL is republished. The response returns `{new_cert_pem,
   assigned_boot_epoch, current_assignment_id, assignment_active_from}`. `[D31, D35, D38]`

**Failure semantics.** A cryptographic or proof failure revokes the token (fail closed: 400 `PROOF_INVALID`, 401
`INVALID_BOOTSTRAP`); a transient KMS or DB failure returns it to `ISSUED` and answers 503 `TEMPORARILY_UNAVAILABLE`
with a random 3 to 8 s `Retry-After`. An aborted activation marks the serial `VOIDED`, and if the leaf was already
signed, stores it as `REVOKED` (`REPLACED_BEFORE_USE`) and deny-lists it; the loser of two enrollments racing on one
token gets 409 `ENROLLMENT_SUPERSEDED`. `[D34, D38]`

**Dev seed tool.** `./gradlew :server:seedDemoDevice` (test classpath, refuses any database but the local Compose one,
never an HTTP endpoint) registers a software passkey (`var/devseed/passkey.key`, purpose `DEV_SEED`) and provisions
through the same code path (`ProvisioningService.beginForSeedTool`, which no HTTP route calls), so its tokens pass the
same re-verification. Its devices and tokens carry a DEV SEED badge. `[D32, D51, D57, D64, D66]`

### Protocol B: OLK-Signed, First-Use-Activated Renewal (Port `8443` mTLS, `POST /api/v1/devices/renew`)

Triggered at **2/3 of the leaf's validity** (8 h for `PT12H`, about 60 s after issuance for the demo's `PT3M`), or
immediately upon receiving `409 ASSIGNMENT_CHANGED` (the simulator stores the new assignment id first). `[D83, D86,
D99]`

1. Wearable fetches a stateless HMAC challenge from `GET /api/v1/devices/renew-challenge` on Port `8443`
   (`{issued_at_ms, random_nonce_b64, hmac_tag_b64}`, 16-byte nonce, no DB write). The tag is an HMAC over the purpose,
   `issued_at_ms`, the nonce, and the serial of the TLS client certificate, with a 32-byte key generated in memory at
   each boot. The wearable then submits `{issuer_key_hash, serial_number, issued_at_ms, random_nonce_b64,
   hmac_tag_b64, olk_new_csr_der_b64, olk_renewal_sig}` over Port `8443`. `[D81]`

2. **Verification (in-process `RenewalService`, before any write):** `[D81, D89]`

   * The body's `issuer_key_hash` and `serial_number` must equal the connection's TLS client certificate, else 403
     `RENEWAL_CERT_MISMATCH`.

   * Verifies `hmac_tag_b64` and `abs(JVM now_ms - issued_at_ms) <= 60000`, else 401 `CHALLENGE_INVALID`.

   * The presenting certificate must be `ACTIVE` with JVM now < `not_after` (a pending certificate cannot renew), else
     409 `CERT_NOT_RENEWABLE`; `olk_renewal_sig` must verify over `OlkRenewalProofBytes` with the stored certificate's
     public key, and the CSR must be valid with a key different from the current OLK and the DEK, else 400
     `PROOF_INVALID`.

   * **Tx 1:** locks the device row (403 unless `ACTIVE`), inserts the nonce into `consumed_challenge_nonces` (409
     `CHALLENGE_REPLAYED` on reuse; `expires_at` = `issued_at_ms` + 5 min, JVM clock, swept every 5 minutes), requires
     an `ACTIVE` assignment with JVM now < `max_renewal_horizon` (409 `DEVICE_UNASSIGNED` or
     `RENEWAL_HORIZON_EXCEEDED`), and reserves the new serial.

3. **Idempotent Pending Issuance:** KMS signs outside any transaction. **Tx 2** locks the device row and the presenting
   certificate (still `ACTIVE`, else abort and void), marks the serial `RECORDED`, deny-lists any prior unused
   `ISSUED_PENDING_USE` certificate and marks it `REVOKED (REPLACED_BEFORE_USE)`, and inserts the new certificate as
   `ISSUED_PENDING_USE` with `superseded_serial = serial_number`, while the presenting certificate remains `ACTIVE`.
   Returns `{new_cert_pem, current_assignment_id, assignment_active_from}`. A KMS or DB failure is 503 with a 3 to 8 s
   `Retry-After`, and the serial is voided. `[D38, D85, code]`

   Renewal race: whoever holds the current OLK can renew, and each renewal revokes the previous unused pending
   certificate. A clone copied shortly before a scheduled renewal can therefore win the race: the real device's pending
   certificate is revoked as `REPLACED_BEFORE_USE`, which looks like a lost renewal response, and once the clone's
   certificate is activated the presenting certificate is no longer `ACTIVE`, so further renewals from it are refused
   (`CERT_NOT_RENEWABLE`). A real device that falls back to its old certificate after grace trips the post-drain trap;
   the simulator instead exits 3. A trap on "renewal attempted from a certificate whose successor was issued to a
   different key" is Designed. `[D94, D102]`

4. **Switchover on First Telemetry Batch:** when a batch signed with the `ISSUED_PENDING_USE` certificate is accepted,
   the ingest service calls `CertificateActivationService` asynchronously (in-process; no Signer RPC), after the 200
   and before that batch's clinical evaluation is queued. One transaction locks the device row, then the new
   certificate (still pending, else nothing to do), deny-lists the old certificate from `grace_expires_at = JVM now +
   renewal-grace` before commit, moves the old certificate `ACTIVE` -> `RENEWED` and then the new one
   `ISSUED_PENDING_USE` -> `ACTIVE` (`activated_at`, Postgres time). After commit a timer closes the old certificate's
   live sockets at `grace_expires_at`. Concurrent first batches serialize on the device row; only the first finds the
   certificate still pending. `[D84, D89, code]`

### Protocol C: Challenge-Response Offline Re-Enrollment (Port `8444`, `/challenge` and `/re-enroll`)

1. Wearable obtains a stateless HMAC challenge from `GET /api/v1/devices/challenge?device_id=` (`{issued_at_ms,
   random_nonce_b64 (16 bytes), hmac_tag_b64}`). The tag covers the purpose `vitalsshield.reenroll-challenge.v1`,
   `device_id`, `issued_at_ms`, and the nonce, with a per-boot key separate from the renewal key. Rate limits: 10 per
   minute per remote address and 100 per minute globally (60 and 300 in the `demo` profile), 429 with `Retry-After`;
   zero DB writes. The limiter is in memory and per process. `[D90, D99]`

2. Wearable submits `{device_id, issued_at_ms, random_nonce_b64, hmac_tag_b64, boot_epoch, olk_csr_der_b64, dek_sig}`,
   with `dek_sig` over `ReEnrollProofBytes` (Section 3, encoding 6) signed by its `DEK`. `[D21]`

3. **Verification and State-Reset Epoch Resync (in-process `ReEnrollService`):**

   * Before any write: verifies `hmac_tag_b64` for this `device_id` and the 60 s age (401 `CHALLENGE_INVALID`),
     verifies `dek_registry_kms_sig` with the Key #4 public key (403 `DEVICE_NOT_ENROLLABLE`, the same answer as for an
     unknown device), verifies `dek_sig` against `devices.dek_spki_der_b64`, and requires a valid CSR with a key never
     used before by this device (400 `PROOF_INVALID`).

   * **Tx 1:** locks the device row, inserts the nonce into `consumed_challenge_nonces` (409 `CHALLENGE_REPLAYED`),
     requires `trust_state = 'ACTIVE'` (403 `DEVICE_NOT_ACTIVE`; a `REAUTH_REQUIRED` device must be restored first),
     and an `ACTIVE` assignment with JVM now < `max_renewal_horizon`.

   * **Epoch Handling** (`EpochRules`; `s` = stored, `p` = presented): `[D97]`

     * `boot_epoch` is server-assigned. Wearables always present the last epoch they received and never increment it
       themselves. `p > s` is rejected with `409 BOOT_EPOCH_INVALID` and raises the anomaly response
       (`REAUTH_REQUIRED`).

     * If `devices.epoch_resync_allowed == TRUE` (set by clinician `restore-active`) and `p <= s`, the flag is consumed
       in Tx 1 together with the nonce, and Tx 2 assigns `boot_epoch = s + 1` with `last_sequence_num = 0` and
       `replay_bitmap = 0`. If the KMS signature or Tx 2 fails, the flag is given back (only if the epoch did not
       move), so a transient failure never turns the retry into a regression.

     * Otherwise, `p < s` is rejected with `409 BOOT_EPOCH_REGRESSION` and raises the anomaly response.

     * `p == s` (normal recovery from offline expiry) keeps the epoch, `last_sequence_num`, and `replay_bitmap`.

   * **Active-Session Collision Check** (after the epoch branch, for `SAME` and `RESYNC`): fires only if the device
     still has a usable certificate (`ACTIVE` or `ISSUED_PENDING_USE` with `not_after` > JVM now, or `RENEWED` within
     grace) **and** either the session registry holds a live socket for any of its certificates or `last_ingested_at
     >= Postgres now() - 30 s`. It then raises the anomaly response (`REENROLL_COLLISION`) and answers 409
     `REAUTH_REQUIRED`; the anomaly commits with the nonce. An expired certificate alone is never a collision, so a
     device whose leaf expired seconds after its last batch (for example, across a laptop sleep) recovers normally.
     This replaces v1's literal rule ("current certificate not revoked and `last_ingested_at` within 30 s"). `[D89,
     D91]`

4. **Activation:** KMS signs outside any transaction; Tx 2 deny-lists the device's prior certificates and revokes them
   (`SUPERSEDED_BY_REENROLL`), inserts the new certificate as `ACTIVE` immediately (no pending phase: the device has
   nothing to fall back on; `issued_via = 'REENROLL'`, `reenroll_reason` = `cert_expired`, `epoch_resync`, or
   `no_usable_cert`), marks the serial `RECORDED`, and updates `devices.boot_epoch`. After commit, open sockets of the
   old certificates are closed and the CRL is republished. Returns `{new_cert_pem, assigned_boot_epoch,
   current_assignment_id, assignment_active_from}`. `[D38, code]`

### Non-Destructive Anomaly Response and Clinician Recovery

* **Action (in-process `AnomalyService`; there is no `/internal/v1/signer/revoke` endpoint):** in one transaction
  (devices row, then certificates, then the `clinical_alerts` insert, audit lock last): every `ACTIVE`,
  `ISSUED_PENDING_USE`, or `RENEWED` certificate of the device is deny-listed before commit and marked `REVOKED` with
  `revocation_reason = 'SUSPECTED_CLONE'` (CRL `keyCompromise`); `trust_state` becomes `REAUTH_REQUIRED`; a
  `SECURITY_ANOMALY_ALERT` is inserted (`triggering_batch_ids` empty, `baseline_version` NULL, `condition_code` one of
  `REENROLL_COLLISION`, `SEQUENCE_REGRESSION`, `POST_DRAIN_USE`, `BOOT_EPOCH_INVALID`, `BOOT_EPOCH_REGRESSION`); and a
  `SECURITY_ANOMALY` audit entry is appended with actor `system`. After commit the live sockets are closed and the CRL
  is republished. Telemetry is not changed; historical batches remain `ACCEPTED`. `certificateHold` is not used,
  because nothing is ever un-revoked: recovery always issues a new certificate. If the device is already not `ACTIVE`,
  only an audit entry is appended. The security alert names no batches, so a later quarantine never retracts it.
  The transaction follows the global lock order (Section 6). `[D70, D82, D92]`

* **Trap mechanics.** The sequence-regression trap counts, per device and in memory, rejections of type
  `DUPLICATE_SEQUENCE_REPLAY`, `SEQUENCE_TOO_OLD`, or `BOOT_EPOCH_MISMATCH` from certificates that the per-request
  check accepted; 3 distinct `batch_id`s within 60 s fire it, and idempotent retries are returned before the trap is
  reached. The post-drain trap is recorded on the event loop (trust manager or per-request check sees a `SUPERSEDED`
  certificate; one bounded in-memory queue offer, capacity 1024) and decided on `boundedElastic` every 250 ms: the row
  is `RENEWED`, the presentation was more than 5 s after `grace_expires_at`, and the successor is `ACTIVE`, and it
  fires at most once per certificate. The sequence-regression and post-drain traps each have an `enabled` switch; both
  are on in the default and `demo` profiles. `[D93, D94, D99]`

* **Recovery Path from `REAUTH_REQUIRED`:** A clinician inspects the alert on Port `8445` and submits either: `[D1,
  D58, D60]`

  1. **Clear Device (`POST /api/v1/admin/devices/{id}/restore-active/begin`, then `/finish`):** passkey step-up whose
     challenge is the restore approval digest (Section 3, encoding 7). Allowed only from `REAUTH_REQUIRED`; sets
     `trust_state = 'ACTIVE'` and `epoch_resync_allowed = TRUE` and appends `DEVICE_RESTORED` in one transaction, so a
     benignly reset or state-reset device can recover via `/re-enroll` with server-assigned `stored_epoch + 1`. The
     first re-enrollment spends the permission; a second copy presenting the old epoch is then a regression.

  2. **Confirm Compromise (`POST /api/v1/admin/devices/{id}/quarantine/begin`, then `/finish`):** passkey step-up
     whose challenge binds the device id, `lookback_minutes` (1 to 1440), the reason, and a server nonce; parameters
     are held server-side between begin and finish, and finish accepts only the assertion. Allowed from `ACTIVE` or
     `REAUTH_REQUIRED`. See Section 6 for the steps. In `bearer` auth mode the single-step
     `POST /api/v1/admin/devices/{id}/quarantine` (setup-code bearer) remains; in the default `webauthn` mode it is
     404. Quarantine also revokes the device's outstanding `ISSUED` and `CLAIMING` bootstrap tokens, so a pending
     token cannot re-enroll the device. `[D41, D45]`

### Revocation Enforcement Path

| Layer | Mechanism | Timing |
| :--- | :--- | :--- |
| **Handshake** | `DynamicMtlsTrustManager` rejects certificates that fail PKIX or leaf policy, or are on the in-memory deny-list. It does no I/O; it does not look up an "accepted status". `[D24]` | Every new TCP connection (every connection is a full handshake, `[D26]`) |
| **Post-handshake gate** | `PostHandshakeGate` registers the channel, re-checks the deny-list, and invalidates the TLS session so it cannot resume. `[D24, D26]` | Every completed handshake |
| **Per-request** | `CertStatusResolver` reads the `certificates` row and checks status and validity window before the controller runs. No cache. `[D23]` | Every request on 8443 |
| **Live socket eviction** | The in-process revoke path deny-lists first (fail closed), commits the `REVOKED` row, then calls `ActiveSessionRegistry.evictByCert()`, which closes the Netty `Channel`s and waits for the close futures. Revocation latency is measured from revoke start to channel close complete. Multi-gateway broadcast over Redis pub/sub is Designed. `[D8, D11]` | Under 500 ms in tests; single-digit milliseconds in the stage rehearsal |
| **Grace eviction** | A timer closes a `RENEWED` certificate's sockets at `grace_expires_at`. `[D84]` | At the end of the grace window |
| **Expiry sweep** | Certificates past `not_after` become `EXPIRED`, deny-listed, sockets evicted. `[D84, D87]` | Every 30 s and at boot |
| **Deny-list refresh** | Union refresh of the deny-list from the database; never removes entries. A backstop for the handshake deny-list, not for eviction. `[D28]` | Every 30 s |
| **Backstop poller** | Built in Phase 9, so not marked Designed `[D13]`. `BackstopPoller` selects certificates `REVOKED` with `revoked_db_at >= (previous poll's Postgres now() - 30 s)`, deny-lists each (`deniedFrom` = the earlier of `revoked_at` and JVM now), and closes any live socket. Idempotent. `revoked_db_at` is stamped by a V7 trigger with `clock_timestamp()` whenever a row becomes `REVOKED` by any path, including direct SQL, so the window compares Postgres time with Postgres time; `revoked_at` is never compared. `[D89, D96]` | Every 3 s; a revocation made by direct SQL was enforced in about 2.5 s in its test |
| **Interoperable record** | The Device Intermediate publishes a signed X.509 v2 CRL (`nextUpdate` = 24 h) and the Root a CRL (`nextUpdate` = 180 days). Each CRL is cached in memory; an HTTP GET only reads the cache and never signs or increments the CRL Number. A CRL is regenerated after a revocation of a certificate it covers commits (after eviction, so it never adds to eviction latency), and when its `nextUpdate` is less than 12 h (intermediate) or 90 days (root) away, checked every 10 minutes. Regenerations are coalesced: one in flight per CRL plus at most one more. The CRL Number increment and the entry read share one transaction; KMS signs after commit. Entries: `REVOKED` certificates not yet past `not_after`, plus `VOIDED` serials (reason `superseded`). The CRL is the published record, not the enforcement path. `[D27, D38]` | Republished after revocations (coalesced) and before `nextUpdate` |

The CRL endpoint has no rate limit; a GET costs a memory read and a TLS handshake. Production publishes CRLs to object
storage behind a CDN and rate-limits 8444 at the L4 load balancer (Designed). Each gateway process caches its own CRL;
CRL Numbers come from the database, so they always increase, but with several gateways the number served could briefly
differ between them. One CRL in shared storage is Designed. The Root CRL is derived from `REVOKED` `ca_issuers` rows,
because `ca_issuers` has no revocation timestamp or reason columns (a production gap). `[D22, D29, D30]`

### Degraded-Mode Behavior

| Failure | Behavior |
| :--- | :--- |
| **KMS unavailable** | Existing certificates keep working until `notAfter`. Enrollment, renewal, and re-enrollment answer 503 `TEMPORARILY_UNAVAILABLE` with a random 3 to 8 s `Retry-After`; the reserved serial is voided and an enrollment token returns to `ISSUED`. Renewal is due at 2/3 of validity, leaving a 4-hour buffer for `PT12H` (about 60 s for the demo's `PT3M`). The KMS health monitor shows the outage; it never rebuilds at runtime. There is no separate Signer to be unavailable. `[D34, D49, D83, code]` |
| **PostgreSQL unavailable** | A batch is acknowledged (200) only after its insert commits, so no uncommitted batch is ever acknowledged. Enrollment, renewal, and re-enrollment map transient DB failures to 503 with `Retry-After`; telemetry ingest has no such mapping, so a database error surfaces as a server error without `Retry-After`. The simulator retries the same frame; a flash ring buffer that drains in FIFO order is Designed. `[D44, code]` |
| **Revocation event lost** | The backstop poller enforces a revocation within one 3 s poll (window: previous poll's Postgres time minus 30 s); the per-request check refuses it on the next request regardless. `[D96]` |
| **Intermediate CA compromised** | **Designed, not built:** promote the standby Intermediate (#3), bulk-revoke #2 leaves as `CA_COMPROMISE`, devices re-enroll through Protocol C with jittered `Retry-After`. In the build the only hierarchy change is the `local`-profile rebuild on key loss, which revokes every leaf (`HIERARCHY_REBUILD`) and clears every DEK anchor, so devices re-provision through Protocol A. `[D12, D20, code]` |
| **Clock skew between JVM and Postgres** (new) | `ClockSkewMonitor` measures Postgres `clock_timestamp()` minus the JVM clock at boot and every 60 s; the dashboard shows the value green up to 2 s, amber up to 10 s, red above. The pre-stage checklist requires a restart of Docker Desktop when it is amber or red. Comparisons follow the same-clock rule (Section 5), so skew does not change any accept or reject decision. `[D89, D98]` |

## 5. JWS Telemetry Ingestion and Conflict-Safe Sliding Window

### JWS (`ES256`) Telemetry Envelope (`POST /api/v1/telemetry/ingest` on Port `8443`)

*(Note: The `x5t#S256` thumbprint and `firmware_hash` values below are illustrative format-only examples.)*

**JWS Protected Header:**

```json
{
  "alg": "ES256",
  "typ": "vitalsshield.telemetry+jws",
  "x5t#S256": "f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk"
}
```

**JWS Signed Payload:**

```json
{
  "batch_id": "b7f9c2d0-81e4-4c1a-9f32-112233445566",
  "device_id": "dev_wearable_019",
  "assignment_id": "018f7b2a-4c91-7d3e-8a12-9b4e5f6a7c8d",
  "boot_epoch": 3,
  "sequence_number": 1042,
  "measured_at": "2026-11-13T18:40:00.000Z",
  "transmitted_at": "2026-11-13T18:45:12.150Z",
  "firmware_hash": "sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
  "metrics": {
    "heart_rate_bpm": 76,
    "hrv_rmssd_ms": 42.5,
    "spo2_pct": 98.0,
    "signal_perfusion_index": 3.4,
    "step_cadence_spm": 0,
    "motion_g_rms": 0.02
  }
}
```

**Ingest order as built** (`TelemetryIngestService`, on `boundedElastic`): `[D35, D40, D43, D46, code]`

1. The per-request status check has already accepted the TLS client certificate (Section 4).
2. Certificate binding: the TLS leaf thumbprint must equal the stored `cert_thumbprint_s256`, else 401
   `JWS_CERT_MISMATCH`.
3. JWS verification with the TLS leaf's public key only, under the header policy of Section 2 layer 2 (401
   `JWS_INVALID` or `JWS_CERT_MISMATCH`).
4. Strict payload parsing: unknown, missing, or null fields, trailing tokens, and float-to-int coercion are rejected
   (400 `PAYLOAD_INVALID`); `device_id` must be the certificate's device (403 `DEVICE_MISMATCH`); `sequence_number` and
   `boot_epoch` must be at least 1; `transmitted_at` must be within 5 minutes of the JVM clock; `measured_at` may be at
   most 1 minute after `transmitted_at`; the firmware hash must match its format; every metric must be present and
   finite.
5. The `assignment_id` must be the device's `ACTIVE` assignment (409 `DEVICE_UNASSIGNED`, or 409
   `ASSIGNMENT_CHANGED` with `current_assignment_id` and `assignment_active_from`).
6. Classification at ingest by plausibility bounds and perfusion only: `REJECTED_IMPLAUSIBLE`, `SIGNAL_DEGRADED`, or
   `ACCEPTED` (thresholds in Section 6).
7. The single-CTE window update and insert below, as one autocommit statement.
8. On a new row: the 200 response, then (off the response path) certificate activation if the signing certificate is
   `ISSUED_PENDING_USE`, then clinical evaluation is queued (not for `REJECTED_IMPLAUSIBLE` rows or idempotent
   retries).

An mTLS connection whose certificate is revoked mid-stream is closed within the revocation latency (revoke start to
channel close complete, under 500 ms in tests), and the next request on any connection is refused by the per-request
check. `[D11, D23]`

### Single-CTE Conflict-Safe Sliding Window and Insert

Sequence uniqueness is keyed on `(device_id, boot_epoch, sequence_number)` with `ON CONFLICT DO NOTHING` so concurrent
duplicate retries never trigger transaction-aborting `SQLSTATE 23505` errors. The statement in the build is v1's,
byte for byte (`TelemetryIngestService.WINDOW_CTE`); the `trust_state` enum is bound as an untyped parameter
(`Types.OTHER`) instead of adding a cast. `last_ingested_at` is Postgres time. `[D89, code]`

```sql
WITH window_update AS (
    UPDATE devices
    SET
        replay_bitmap = CASE
            WHEN (:seq - last_sequence_num) >= 64 THEN 1::BIGINT
            WHEN (:seq - last_sequence_num) > 0   THEN (replay_bitmap << (:seq - last_sequence_num)::INT) | 1::BIGINT
            ELSE replay_bitmap | (1::BIGINT << (last_sequence_num - :seq)::INT)
        END,
        last_sequence_num = GREATEST(last_sequence_num, :seq),
        last_ingested_at  = NOW(),
        updated_at        = NOW()
    WHERE device_id = :deviceId
      AND trust_state = 'ACTIVE'
      AND boot_epoch = :bootEpoch
      AND (
          :seq > last_sequence_num
          OR (
              (last_sequence_num - :seq) BETWEEN 0 AND 63
              AND ((replay_bitmap >> (last_sequence_num - :seq)::INT) & 1::BIGINT) = 0
          )
      )
    RETURNING device_id, boot_epoch
)
INSERT INTO telemetry_records (
    batch_id, device_id, assignment_id, issuer_key_hash, serial_number,
    boot_epoch, sequence_number, measured_at, transmitted_at, heart_rate_bpm,
    hrv_rmssd_ms, spo2_pct, perfusion_index, step_cadence_spm,
    motion_g_rms, firmware_hash_meta, payload_sha256, jws_compact, trust_state
)
SELECT
    :batchId, w.device_id, :assignmentId, :issuerKeyHash, :serialNumber,
    w.boot_epoch, :seq, :measuredAt, :transmittedAt, :hr,
    :hrv, :spo2, :perfusion, :cadence,
    :motion, :fwHash, :payloadSha256, :jwsCompact, :trustState
FROM window_update w
ON CONFLICT DO NOTHING
RETURNING batch_id;
```

* **Atomic Acceptance:** If `batch_id` is returned, both the sliding-window bit update and the telemetry row insert
  committed atomically. Bit `k` of `replay_bitmap` records sequence `last_sequence_num - k`; a 64-bit window covers
  `last_sequence_num - 63` to `last_sequence_num`.

* **Duplicate / Retry Behavior:** Concurrent duplicates are serialized by the row lock that `window_update` takes on
  the `devices` row; the second statement re-evaluates its `WHERE` clause after the first commits, finds the sequence
  bit set, and matches `0` rows. `ON CONFLICT DO NOTHING` only takes effect when a wearable reuses a `batch_id` under a
  new sequence number: the window update still commits, consuming that sequence number (it is never reused), and the
  batch is rejected. In every no-row case, the service queries `telemetry_records` for `(:deviceId, :batchId)`: `[D93,
  code]`
  * found, with identical `payload_sha256` and `boot_epoch`: `200 OK (idempotent_retry: true)` with the stored
    `trust_state` (the simulator relies on this: after a failure it resends the same frame, same `batch_id` and
    sequence number, until it succeeds `[D44]`);
  * found, otherwise: `409 BATCH_ID_REUSED`;
  * not found and the device is not `ACTIVE`: `403 DEVICE_NOT_ACTIVE`;
  * not found, otherwise: `409 BOOT_EPOCH_MISMATCH` (epoch differs), `409 SEQUENCE_TOO_OLD` (more than 63 below
    `last_sequence_num`), or `409 DUPLICATE_SEQUENCE_REPLAY`. Only these three reach the sequence-regression trap.

`ReplayWindowPropertyIT` compares 2000 random operations against an independent model of the window. `[code]`

**Same-clock rule.** Compare a timestamp only with the clock that produced it. Three clocks exist: the JVM `Clock` bean
(writes `not_before`, `not_after`, `revoked_at`, `grace_expires_at`, `voided_at`, token `expires_at`,
`max_renewal_horizon`, nonce `expires_at`, deny-list `deniedFrom`, challenge `issued_at_ms`); Postgres `now()` and
`clock_timestamp()` (every `DEFAULT NOW()` column and `= NOW()` assignment: `ingested_at`, `last_ingested_at`,
`issued_at`, `activated_at`, `claimed_at`, `reserved_at`, `revoked_db_at`, alert `created_at`); and the device clock
(`measured_at`, `transmitted_at`). The single intended cross-domain comparison is the `transmitted_at` freshness bound
(device against JVM, 5 minutes). Every comparison is listed in `docs/CLOCK_INVENTORY.md`, and each one fixed in
Phase 9 has a targeted assertion in `ClockDisciplineIT`, which runs the JVM clock 10 minutes behind Postgres. v1's
`NOW()` comparisons against JVM-written columns (for example `NOW() < cert.not_after`, `grace_expires_at = NOW() +
INTERVAL '60 seconds'`) are replaced accordingly. `[D87, D89, D98]`

## 6. Activity-Context Clinical Drift Engine and Lineage-Tracked Alert Retraction

*Z-score thresholds, the calibration window size, and acute physiological limits are configurable engineering defaults
(`vitalsshield.clinical.*`) and have not been clinically validated.*

### Linear Evaluation Pipeline

Step 1 and the perfusion split of step 3 run at ingest (they decide the stored `trust_state`). Everything else runs in
`ClinicalEvaluator` after the ingest statement commits, in its own transaction, queued per assignment so that
"consecutive" and "sustained" follow ingestion order. The queue runs on its own scheduler and is capped at
`queue-capacity` (default 1000 per process); overflow and evaluations lost to a crash stay unevaluated
(`clinical_evaluated_at` NULL), are counted on the dashboard, and are never replayed out of order. A durable evaluation
outbox is Designed. A failed evaluation rolls back and is counted (`clinical.evaluation_failures`). `[D46, D69, D79]`

1. **Hardware / ADC Plausibility Bounds:** `heart_rate_bpm` outside `[15, 300]` or `spo2_pct` outside `[40, 100]` is
   stored as `REJECTED_IMPLAUSIBLE` and never evaluated.

2. **Activity and Motion Context Classification:** Classifies each batch as `RESTING` (`step_cadence_spm == 0` and
   `motion_g_rms < 0.05g` continuously for at least 5 minutes of `measured_at` time, tracked in
   `patient_device_assignments.resting_since`) or `EXERTION`, stored in `telemetry_records.activity_context`. If
   `measured_at` goes backwards relative to the previous evaluated batch, `resting_since` resets. `[D68, D69]`

3. **Signal Perfusion and Acute Threshold Evaluation:**

   * If `perfusion_index < 0.5`, the batch is stored as `SIGNAL_DEGRADED`; if 3 consecutive degraded batches also
     exhibit `spo2_pct <= 90.0` or `heart_rate_bpm <= 40` / `>= 150`, emits `LOW_PERFUSION_CRITICAL_ALERT` when the
     streak reaches 3, then not again until the streak resets. An `ACCEPTED` batch resets this streak. `[D71]`

   * If `perfusion_index >= 0.5`, the batch is stored as `ACCEPTED` and evaluated against context-aware acute bounds
     (`RESTING` HR `>= 140` or `<= 40`; `EXERTION` HR `> 0.95 * (208 - 0.7 * age)`, age from
     `patient_birth_year`; any-state `spo2_pct <= 90.0`), emitting `ACUTE_PHYSIOLOGICAL_ALERT` (`baseline_version =
     NULL`, `condition_code` naming the condition). It is suppressed if an `ACTIVE` or `ACKNOWLEDGED` alert with the
     same assignment and `condition_code` has a triggering batch measured within the last 5 minutes. `[D68, D71]`

4. **Resting Baseline Calibration and Drift Z-Scores:** Calibration uses only `ACCEPTED` `RESTING` batches that did
   not trigger an acute alert. After `calibration-size` such batches (30 by default, 10 in the `local` and `demo`
   profiles) it locks `ref_*` sample mean and sample SD (n-1), with SD floors HR 3.0 bpm, HRV 5.0 ms, SpO2 1.0 pct
   (`baseline_state = 'LOCKED'`; the version stays). It then flags `POTENTIAL_PHYSIOLOGICAL_DRIFT` (recording the
   active `baseline_version`) when at least 2 of 3 metrics breach directional thresholds (Z_HR >= +2.0, Z_HRV <= -1.8,
   Z_SpO2 <= -1.5) across 4 consecutive resting batches; the alert resets the streak. The drift streak counts only
   `ACCEPTED` `RESTING` batches on a `LOCKED` baseline; `EXERTION` and `SIGNAL_DEGRADED` batches neither count nor reset
   it, and a non-breaching `RESTING` batch resets it. A streak restarts if any batch id stored in it is no longer
   `ACCEPTED` or `SIGNAL_DEGRADED`, so an alert never lists quarantined evidence. `[D6, D72, D73, D78]`

**Alert actions.** Acknowledge (`POST /api/v1/admin/alerts/{id}/acknowledge`) and resolve (`/resolve`) need a passkey
session (no step-up) and append `ALERT_ACKNOWLEDGED` or `ALERT_RESOLVED` to the audit log. Alerts appear on the
dashboard; there is no paging or escalation. `[D76]`

**Evaluation transaction.** Devices row `FOR KEY SHARE` (stop if not `ACTIVE`, so evaluations still queued when a
quarantine commits create nothing), the telemetry row `FOR UPDATE` (stop if no longer trusted or already evaluated),
the assignment row `FOR NO KEY UPDATE`, then the alert inserts and the assignment and telemetry updates. `FOR NO KEY
UPDATE` serializes evaluators and the quarantine statement's `UPDATE` of the assignment without blocking the FK
key-share lock that an ingest `INSERT` takes on the same assignment row. `[D70]`

**Global lock order.** Every transaction acquires row locks in this order, and every transaction-opening class states
its part in a header comment: `devices` -> `certificates` -> `telemetry_records` -> `patient_device_assignments` ->
`clinical_alerts` -> the audit advisory lock, always last. A transaction that holds the audit lock never waits for a
row lock, so no wait cycle can form. `QuarantineAuditAtomicityIT.noDeadlockUnderMixedLoad` (10 quarantines, 10
provisionings, 10 assignment closes at once) and `LockOrderIT` check that no deadlock occurs. `[D67, D70, D82]`

### Dual-Timestamp Quarantine and Scoped Alert Retraction

**As built** (`QuarantineService`, started by the step-up finish of Section 4): `[D1, D42, D45, D67, D89]`

1. **Revoke first.** `SignerRevocationService.revokeAllForDevice` locks the device row and its certificate rows,
   deny-lists every non-revoked certificate (`ACTIVE`, `ISSUED_PENDING_USE`, `RENEWED`) before commit, marks them
   `REVOKED` (`KEY_COMPROMISE`), then closes every live socket and waits for the close futures. Revocation latency is
   measured once, from request receipt to the last close.
2. **One READ COMMITTED transaction:** `SELECT ... FROM devices ... FOR UPDATE` and re-check the state (`ACTIVE` or
   `REAUTH_REQUIRED`); set `trust_state = 'QUARANTINED'`, record the reason, and clear the DEK columns; revoke the
   device's outstanding `ISSUED` and `CLAIMING` bootstrap tokens; read `:quarantineTs` as Postgres `now()` inside this
   transaction; run the sanitize statement below as a separate statement; append `DEVICE_QUARANTINED` (actor, SHA-256
   of the approving assertion) last. Locking and flipping the state before the sanitize statement means an in-flight
   ingest either committed before the lock (and the sanitize statement, which takes a fresh snapshot, sees its row) or
   waits on the lock and then fails the CTE's `trust_state = 'ACTIVE'` check.
3. **After commit:** the CRL is republished (coalesced).

If step 2 fails, the certificates stay revoked (fail closed): the device is cut off even though its data was not
sanitized, and the overview flags it `needs_attention` (`CERT_REVOKED_STATE_ACTIVE`) with a "retry quarantine" hint.
`[D67, D77]`

The sanitize statement (`ingested_at` OR `measured_at` within the window) resets any calibration-poisoned baseline
back to `'CALIBRATING'` with an incremented `baseline_version`, zeroes that assignment's clinical streaks, and retracts
only alerts directly triggered by quarantined batches or drift alerts computed against the tainted
`baseline_version` (leaving unrelated acute and all security alerts intact). It is v1's text with three changes: the
four V5 streak columns are reset in `tainted_baselines`, the final `UPDATE` is wrapped as `retracted_alerts` with
`RETURNING`, and a `SELECT` returns the three counts. `:quarantineTs` is bound as a `timestamptz` holding Postgres
`now()`, so `ingested_at` (Postgres) is compared with Postgres time; `measured_at` is device time and is compared with
the same bound by design, because the compressed simulator clock and wall-clock stalls (such as a laptop sleep) show in
`ingested_at` but not in `measured_at`. `[D68, D88, D89]`

```sql
WITH quarantined_batches AS (
    UPDATE telemetry_records
    SET trust_state = 'QUARANTINED'
    WHERE device_id = :deviceId
      AND trust_state IN ('ACCEPTED', 'SIGNAL_DEGRADED')
      AND (
          ingested_at >= :quarantineTs - (:lookbackMinutes * INTERVAL '1 minute')
          OR measured_at >= :quarantineTs - (:lookbackMinutes * INTERVAL '1 minute')
      )
    RETURNING batch_id, assignment_id
),
tainted_baselines AS (
    UPDATE patient_device_assignments a
    SET baseline_state        = 'CALIBRATING',
        baseline_version      = a.baseline_version + 1,
        calibration_batch_ids = '{}',
        ref_hr_mean           = NULL,
        ref_hr_sd             = NULL,
        ref_hrv_mean          = NULL,
        ref_hrv_sd            = NULL,
        ref_spo2_mean         = NULL,
        ref_spo2_sd           = NULL,
        degraded_critical_streak    = 0,
        degraded_critical_batch_ids = '{}',
        drift_breach_streak         = 0,
        drift_breach_batch_ids      = '{}'
    WHERE a.device_id = :deviceId
      AND a.calibration_batch_ids && ARRAY(SELECT batch_id FROM quarantined_batches)
    RETURNING a.assignment_id, (a.baseline_version - 1) AS old_baseline_version
),
retracted_alerts AS (
    UPDATE clinical_alerts ca
    SET alert_status = 'RETRACTED_BY_QUARANTINE',
        retracted_at = NOW()
    WHERE ca.device_id = :deviceId
      AND ca.alert_status IN ('ACTIVE', 'ACKNOWLEDGED')
      AND (
          ca.triggering_batch_ids && ARRAY(SELECT batch_id FROM quarantined_batches)
          OR (
              ca.alert_type = 'POTENTIAL_PHYSIOLOGICAL_DRIFT'
              AND EXISTS (
                  SELECT 1 FROM tainted_baselines tb
                  WHERE tb.assignment_id = ca.assignment_id
                    AND tb.old_baseline_version = ca.baseline_version
              )
          )
      )
    RETURNING ca.alert_id
)
SELECT (SELECT count(*) FROM quarantined_batches) AS batches_quarantined,
       (SELECT count(*) FROM tainted_baselines)   AS baselines_reset,
       (SELECT count(*) FROM retracted_alerts)    AS alerts_retracted;
```

**Demo clock compression.** The simulator's `measured_at` starts 12 h behind wall-clock time and advances by at most
60 s per batch (about one batch per second), never past the current time; it persists its last `measured_at` and
continues from `max(last + 60 s, now - 12 h)`. This lets the 5-minute resting rule and the calibration window complete
on stage. Once it has caught up, a wall-clock stall shows in `measured_at` as one 60 s step, not as the length of the
stall, and in `ingested_at` as the real gap; that is why quarantine selects on both timestamps. Scenarios can be
switched live. `[D6, D74, D88]`

## 7. PostgreSQL Schema and Tamper-Evident Audit Chain

### Tamper-Evident Audit Log (`security_audit_log`)

Each entry stores `entry_hash = hex(SHA-256(prev_entry_hash || canonical_json({event_type, actor_id, payload}) ||
created_at))`, chained from a genesis value of 64 zeros, and is appended under a PostgreSQL transaction-scoped
advisory lock (`pg_advisory_xact_lock`), which prevents concurrent writers, in this or another process, from forking
the chain. The append runs inside the transaction of the action it records, as that transaction's last statement, so
an action and its entry commit or roll back together (quarantine included). Entries: `PASSKEY_REGISTERED`,
`DEVICE_PROVISIONED`, `ASSIGNMENT_CREATED`, `ASSIGNMENT_CLOSED`, `DEVICE_QUARANTINED`, `DEVICE_RESTORED`,
`ALERT_ACKNOWLEDGED`, `ALERT_RESOLVED` (each with the acting clinician; approvals carry the SHA-256 of the approving
assertion), and `SECURITY_ANOMALY` (actor `system`). `created_at` in the hash is JVM time and is never compared with a
clock. Triggers reject `UPDATE`, `DELETE`, and `TRUNCATE` on the table, so the log is append-only at the database
level; demo resets drop and recreate the Postgres volume (`scripts/reset-demo-state.sh`). The dashboard verifies the
chain and shows "chain valid" with the entry count. The admin routes that write these entries are listed in Section 4
(provisioning, assignment close, quarantine, restore-active) and Section 6 (alert actions). `[D4, D62, D67, D75, D76,
D92]`

Signing the chain head with KMS Key #4 every 60 seconds and writing it to AWS S3 Object Lock (`COMPLIANCE` mode) is
Designed, not built; `s3_anchor_version_id` is always NULL. Without it, a database superuser can drop the triggers and
rewrite the whole chain consistently; the hash chain detects edits only by someone who does not recompute every later
hash. `[D62]`

### Schema as built

`V1__baseline.sql` is v1's schema unchanged, plus the `kms_keys` table (the four KMS keys by purpose; reconciliation
reads `ACTIVE` rows only). Later migrations add columns and tables; there is no `V3` (WebAuthn was not cut, so the
`webauthn_*` token columns stay `NOT NULL`). Notes on the baseline as used: `devices.dek_spki_der_b64` holds the DEK
SPKI DER in base64; `certificates.cert_thumbprint_s256` holds base64url(SHA-256(cert DER)), 43 characters, the JWS
`x5t#S256` value; `certificates.revocation_reason` holds the application reason, mapped to RFC 5280 `CRLReason` when a
CRL is built (Section 3); `ca_issuers` has no revocation timestamp or reason, so the Root CRL is derived (a production
gap). `[D7, D9, D14, D19, D22, D35]`

**V1 (baseline):**

```sql
CREATE EXTENSION IF NOT EXISTS btree_gist;

CREATE TYPE ca_status AS ENUM ('ACTIVE', 'STANDBY', 'REVOKED');
CREATE TYPE cert_status AS ENUM ('ISSUED_PENDING_USE', 'ACTIVE', 'RENEWED', 'REVOKED', 'EXPIRED');
CREATE TYPE device_trust_state AS ENUM (
    'PROVISIONED',
    'ACTIVE',
    'REAUTH_REQUIRED',
    'QUARANTINED',
    'DECOMMISSIONED'
);
CREATE TYPE token_status AS ENUM ('ISSUED', 'CLAIMING', 'CONSUMED', 'EXPIRED', 'REVOKED');
CREATE TYPE assignment_status AS ENUM ('ACTIVE', 'CLOSED');
CREATE TYPE baseline_lock_state AS ENUM ('CALIBRATING', 'LOCKED');
CREATE TYPE telemetry_trust_state AS ENUM (
    'ACCEPTED',
    'SIGNAL_DEGRADED',
    'REJECTED_IMPLAUSIBLE',
    'QUARANTINED',
    'REVIEWED'
);
CREATE TYPE alert_severity_type AS ENUM (
    'ACUTE_PHYSIOLOGICAL_ALERT',
    'LOW_PERFUSION_CRITICAL_ALERT',
    'POTENTIAL_PHYSIOLOGICAL_DRIFT',
    'SECURITY_ANOMALY_ALERT'
);
CREATE TYPE alert_lifecycle_status AS ENUM (
    'ACTIVE',
    'ACKNOWLEDGED',
    'RETRACTED_BY_QUARANTINE',
    'RESOLVED'
);

CREATE TABLE clinician_passkeys (
    credential_id_b64        VARCHAR(256) PRIMARY KEY,
    clinician_id             VARCHAR(128) NOT NULL,
    public_key_cose_der_b64  TEXT NOT NULL,
    passkey_registry_kms_sig TEXT NOT NULL,
    sign_count               BIGINT NOT NULL DEFAULT 0,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ca_issuers (
    issuer_key_hash          VARCHAR(64) PRIMARY KEY,
    subject_dn               TEXT NOT NULL,
    kms_primary_arn          TEXT NOT NULL,
    kms_replica_arn          TEXT,
    cert_pem                 TEXT NOT NULL,
    crl_number               BIGINT NOT NULL DEFAULT 1,
    status                   ca_status NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE devices (
    device_id                VARCHAR(64) PRIMARY KEY,
    hardware_model           VARCHAR(64) NOT NULL,
    dek_spki_der_b64         TEXT,
    dek_spki_sha256          VARCHAR(64),
    dek_registry_kms_sig     TEXT,
    provisioned_at           TIMESTAMPTZ,
    boot_epoch               BIGINT NOT NULL DEFAULT 1,
    epoch_resync_allowed     BOOLEAN NOT NULL DEFAULT FALSE,
    last_sequence_num        BIGINT NOT NULL DEFAULT 0,
    replay_bitmap            BIGINT NOT NULL DEFAULT 0,
    last_ingested_at         TIMESTAMPTZ,
    trust_state              device_trust_state NOT NULL DEFAULT 'PROVISIONED',
    quarantine_reason        VARCHAR(128),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE device_bootstrap_tokens (
    token_id                 UUID PRIMARY KEY,
    device_id                VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    token_hash               VARCHAR(64) NOT NULL,
    status                   token_status NOT NULL DEFAULT 'ISSUED',
    issued_by_clinician      VARCHAR(128) NOT NULL,
    webauthn_cred_id_b64     VARCHAR(256) NOT NULL REFERENCES clinician_passkeys(credential_id_b64),
    webauthn_auth_data       TEXT NOT NULL,
    webauthn_client_json     TEXT NOT NULL,
    webauthn_signature       TEXT NOT NULL,
    expires_at               TIMESTAMPTZ NOT NULL,
    claimed_at               TIMESTAMPTZ,
    consumed_at              TIMESTAMPTZ
);

CREATE TABLE consumed_challenge_nonces (
    nonce_b64                VARCHAR(64) PRIMARY KEY,
    device_id                VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    consumed_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at               TIMESTAMPTZ NOT NULL
);

CREATE TABLE certificates (
    issuer_key_hash          VARCHAR(64) NOT NULL REFERENCES ca_issuers(issuer_key_hash),
    serial_number            VARCHAR(64) NOT NULL,
    device_id                VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    cert_thumbprint_s256     VARCHAR(64) NOT NULL,
    cert_pem                 TEXT NOT NULL,
    superseded_serial        VARCHAR(64),
    not_before               TIMESTAMPTZ NOT NULL,
    not_after                TIMESTAMPTZ NOT NULL,
    grace_expires_at         TIMESTAMPTZ,
    status                   cert_status NOT NULL DEFAULT 'ACTIVE',
    revocation_reason        VARCHAR(64),
    revoked_at               TIMESTAMPTZ,
    PRIMARY KEY (issuer_key_hash, serial_number)
);

CREATE UNIQUE INDEX idx_one_active_cert_per_device
    ON certificates(device_id) WHERE status = 'ACTIVE';

CREATE UNIQUE INDEX idx_one_pending_cert_per_device
    ON certificates(device_id) WHERE status = 'ISSUED_PENDING_USE';

CREATE INDEX idx_certs_revoked_at_poll
    ON certificates(revoked_at) WHERE status = 'REVOKED';

CREATE TABLE patient_device_assignments (
    assignment_id            UUID PRIMARY KEY,
    device_id                VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    patient_id               VARCHAR(64) NOT NULL,
    patient_birth_year       INTEGER NOT NULL,
    active_from              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active_until             TIMESTAMPTZ,
    max_renewal_horizon      TIMESTAMPTZ NOT NULL,
    baseline_state           baseline_lock_state NOT NULL DEFAULT 'CALIBRATING',
    baseline_version         INTEGER NOT NULL DEFAULT 1,
    calibration_batch_ids    UUID[] NOT NULL DEFAULT '{}',
    ref_hr_mean              DOUBLE PRECISION,
    ref_hr_sd                DOUBLE PRECISION,
    ref_hrv_mean             DOUBLE PRECISION,
    ref_hrv_sd               DOUBLE PRECISION,
    ref_spo2_mean            DOUBLE PRECISION,
    ref_spo2_sd              DOUBLE PRECISION,
    status                   assignment_status NOT NULL DEFAULT 'ACTIVE',
    EXCLUDE USING gist (
        device_id WITH =,
        tstzrange(active_from, active_until, '[)') WITH &&
    )
);

CREATE UNIQUE INDEX idx_one_active_assignment_per_device
    ON patient_device_assignments(device_id) WHERE status = 'ACTIVE';

CREATE TABLE telemetry_records (
    batch_id                 UUID NOT NULL,
    device_id                VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    assignment_id            UUID NOT NULL REFERENCES patient_device_assignments(assignment_id),
    issuer_key_hash          VARCHAR(64) NOT NULL,
    serial_number            VARCHAR(64) NOT NULL,
    boot_epoch               BIGINT NOT NULL,
    sequence_number          BIGINT NOT NULL,
    measured_at              TIMESTAMPTZ NOT NULL,
    transmitted_at           TIMESTAMPTZ NOT NULL,
    ingested_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    heart_rate_bpm           INTEGER NOT NULL,
    hrv_rmssd_ms             DOUBLE PRECISION NOT NULL,
    spo2_pct                 DOUBLE PRECISION NOT NULL,
    perfusion_index          DOUBLE PRECISION NOT NULL,
    step_cadence_spm         INTEGER NOT NULL DEFAULT 0,
    motion_g_rms             DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    firmware_hash_meta       VARCHAR(128),
    payload_sha256           VARCHAR(64) NOT NULL,
    jws_compact              TEXT NOT NULL,
    trust_state              telemetry_trust_state NOT NULL,
    PRIMARY KEY (device_id, batch_id),
    UNIQUE (device_id, boot_epoch, sequence_number)
);

CREATE INDEX idx_telemetry_quarantine_window
    ON telemetry_records(device_id, ingested_at, measured_at);

CREATE TABLE clinical_alerts (
    alert_id                 UUID PRIMARY KEY,
    device_id                VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    assignment_id            UUID REFERENCES patient_device_assignments(assignment_id),
    baseline_version         INTEGER,
    alert_type               alert_severity_type NOT NULL,
    alert_status             alert_lifecycle_status NOT NULL DEFAULT 'ACTIVE',
    triggering_batch_ids     UUID[] NOT NULL,
    explanation_summary      TEXT NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retracted_at             TIMESTAMPTZ,
    CONSTRAINT chk_alert_baseline_lineage CHECK (
        (alert_type = 'POTENTIAL_PHYSIOLOGICAL_DRIFT' AND baseline_version IS NOT NULL)
        OR (alert_type <> 'POTENTIAL_PHYSIOLOGICAL_DRIFT' AND baseline_version IS NULL)
    )
);

CREATE INDEX idx_alerts_triggering_batches
    ON clinical_alerts USING gin (triggering_batch_ids);

CREATE TABLE security_audit_log (
    sequence_id              BIGSERIAL PRIMARY KEY,
    event_type               VARCHAR(64) NOT NULL,
    actor_id                 VARCHAR(128) NOT NULL,
    payload_json             JSONB NOT NULL,
    prev_entry_hash          VARCHAR(64) NOT NULL,
    entry_hash               VARCHAR(64) NOT NULL,
    s3_anchor_version_id     VARCHAR(128),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TYPE kms_key_purpose AS ENUM ('ROOT_CA', 'DEVICE_INTERMEDIATE', 'SERVER_TLS_CA', 'REGISTRY_ANCHOR');
CREATE TYPE kms_key_status AS ENUM ('ACTIVE', 'RETIRED');

CREATE TABLE kms_keys (
    kms_key_id   TEXT PRIMARY KEY,
    purpose      kms_key_purpose NOT NULL,
    status       kms_key_status NOT NULL DEFAULT 'ACTIVE',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at   TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_one_active_key_per_purpose
    ON kms_keys(purpose) WHERE status = 'ACTIVE';
```

**V2: serial reservation ledger.** Every device leaf serial is reserved (`RESERVED`) in the transaction that claims the
token or challenge, before any KMS call; activation marks it `RECORDED`; an abort or the 2-minute stale sweep marks it
`VOIDED`. CRLs list `REVOKED` certificates plus `VOIDED` serials, so every serial the Device Intermediate signed is
either recorded or revocable. Gateway leaves are not tracked. `[D38, D39]`

```sql
-- Serial reservation ledger (DECISIONS #38). Every device leaf serial is reserved here before any KMS call.
CREATE TYPE issued_serial_status AS ENUM ('RESERVED', 'RECORDED', 'VOIDED');

CREATE TABLE issued_serials (
    issuer_key_hash VARCHAR(64) NOT NULL REFERENCES ca_issuers(issuer_key_hash),
    serial_number   VARCHAR(64) NOT NULL,
    device_id       VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    reserved_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status          issued_serial_status NOT NULL DEFAULT 'RESERVED',
    voided_at       TIMESTAMPTZ,
    PRIMARY KEY (issuer_key_hash, serial_number)
);

CREATE INDEX idx_issued_serials_reserved ON issued_serials(reserved_at) WHERE status = 'RESERVED';

-- Backfill: every certificate that already exists is RECORDED.
INSERT INTO issued_serials (issuer_key_hash, serial_number, device_id, reserved_at, status)
SELECT issuer_key_hash, serial_number, device_id, not_before, 'RECORDED' FROM certificates;
```

**V4: passkey purpose.** `CLINICIAN` or `DEV_SEED`; runtime checks read only this column. `[D66]`

```sql
-- Phase 6.1 (DECISIONS #66): mark what a passkey may be used for. CLINICIAN: sign-in, step-up, provisioning.
-- DEV_SEED: only the dev seed tool's provisioning path, and only in the local profile.
-- (Versions are not contiguous: there is no V3. Flyway only requires increasing versions.)
ALTER TABLE clinician_passkeys
    ADD COLUMN purpose VARCHAR(32) NOT NULL DEFAULT 'CLINICIAN'
        CONSTRAINT clinician_passkeys_purpose_check CHECK (purpose IN ('CLINICIAN', 'DEV_SEED'));

-- One-time backfill of the dev seed credentials written before this column existed: the Phase 3 fake row
-- ('dev-seed') and any Phase 6 software passkey registered by the seed tool. From now on the seed tool writes
-- purpose = 'DEV_SEED' itself and runtime checks read only this column.
UPDATE clinician_passkeys SET purpose = 'DEV_SEED'
 WHERE credential_id_b64 = 'dev-seed' OR clinician_id = 'dev-seed-clinician';
```

**V5: clinical engine and append-only audit.** Streak state on assignments, activity context and evaluation time on
telemetry, `condition_code` on alerts, and the audit triggers. `[D68, D75]`

```sql
-- Phase 7: clinical engine state (DECISIONS #68) and an append-only audit log (DECISIONS #75).

-- Per-assignment streak state, updated by the clinical evaluator under the assignment row lock (DECISIONS #69, #70).
ALTER TABLE patient_device_assignments
    ADD COLUMN resting_since               TIMESTAMPTZ,
    ADD COLUMN degraded_critical_streak    INT    NOT NULL DEFAULT 0,
    ADD COLUMN degraded_critical_batch_ids UUID[] NOT NULL DEFAULT '{}',
    ADD COLUMN drift_breach_streak         INT    NOT NULL DEFAULT 0,
    ADD COLUMN drift_breach_batch_ids      UUID[] NOT NULL DEFAULT '{}',
    ADD COLUMN last_evaluated_measured_at  TIMESTAMPTZ;

-- Activity context is NULL until the batch is evaluated; clinical_evaluated_at NULL means "not evaluated".
ALTER TABLE telemetry_records
    ADD COLUMN activity_context      VARCHAR(16)
        CONSTRAINT telemetry_records_activity_context_check CHECK (activity_context IN ('RESTING', 'EXERTION')),
    ADD COLUMN clinical_evaluated_at TIMESTAMPTZ;

-- Which rule fired (RESTING_HR_HIGH, SPO2_LOW, LOW_PERFUSION_CRITICAL, DRIFT, ...); the acute dedupe key.
ALTER TABLE clinical_alerts
    ADD COLUMN condition_code VARCHAR(32);

-- Append-only audit log. Rows can be inserted and read; UPDATE, DELETE and TRUNCATE fail for every role that does
-- not first disable the trigger (only the table owner or a superuser can). The hash chain detects edits by those.
CREATE FUNCTION security_audit_log_append_only() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    RAISE EXCEPTION 'security_audit_log is append-only';
END;
$$;

CREATE TRIGGER security_audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON security_audit_log
    FOR EACH ROW EXECUTE FUNCTION security_audit_log_append_only();

CREATE TRIGGER security_audit_log_no_truncate
    BEFORE TRUNCATE ON security_audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION security_audit_log_append_only();
```

**V6: renewal.** Issue and activation times (both Postgres-stamped for every protocol), and indexes for the renewal
paths and sweepers. `[D84, D89]`

```sql
-- Phase 8: Protocol B renewal with first-use activation (DECISIONS #81 to #85).

-- When the CA signed the row's leaf, and when a renewed leaf was first used (ISSUED_PENDING_USE to ACTIVE). Rows that
-- exist before this migration get the migration time as issued_at; only renewals made after it are shown in the
-- dashboard's renewal log, so the backfill value is never displayed.
ALTER TABLE certificates
    ADD COLUMN issued_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN activated_at TIMESTAMPTZ;

-- The renewal log and activation look a renewed leaf's predecessor up by (device_id, superseded_serial).
CREATE INDEX idx_certs_device_superseded ON certificates(device_id, superseded_serial)
    WHERE superseded_serial IS NOT NULL;

-- The nonce sweeper deletes rows past expires_at every 5 minutes.
CREATE INDEX idx_consumed_nonces_expires ON consumed_challenge_nonces(expires_at);

-- The expiry sweeper finds live certificates past not_after.
CREATE INDEX idx_certs_live_not_after ON certificates(not_after)
    WHERE status IN ('ACTIVE', 'ISSUED_PENDING_USE', 'RENEWED');
```

**V7: recovery.** `revoked_db_at`, stamped by a trigger with `clock_timestamp()` whenever a row becomes `REVOKED` by
any path, is the backstop poller's window column; `issued_via` and `reenroll_reason` record how each certificate was
issued. `[D89, D96]`

```sql
-- Phase 9: Protocol C re-enrollment, split-brain traps, backstop poller (DECISIONS #89 to #98).

-- Backstop poller (DECISIONS #96) under the same-clock rule (DECISIONS #89): revoked_at is written by the JVM in every
-- in-process path, but a revocation made outside it (direct SQL) may set any value, or none. revoked_db_at is stamped
-- by Postgres itself whenever a row becomes REVOKED, so the poller compares a Postgres time with Postgres now().
ALTER TABLE certificates
    ADD COLUMN revoked_db_at TIMESTAMPTZ,
    -- How the certificate was issued: ENROLL (Protocol A), RENEW (Protocol B), REENROLL (Protocol C).
    ADD COLUMN issued_via    VARCHAR(16),
    -- Protocol C only: why the device re-enrolled, derived by the server (cert_expired, epoch_resync, no_usable_cert).
    ADD COLUMN reenroll_reason VARCHAR(32);

UPDATE certificates SET revoked_db_at = COALESCE(revoked_at, NOW()) WHERE status = 'REVOKED';
UPDATE certificates SET issued_via = CASE WHEN superseded_serial IS NULL THEN 'ENROLL' ELSE 'RENEW' END;

CREATE FUNCTION certificates_stamp_revoked_db_at() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    IF NEW.status = 'REVOKED' AND (TG_OP = 'INSERT' OR OLD.status IS DISTINCT FROM 'REVOKED') THEN
        NEW.revoked_db_at := clock_timestamp();
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER certificates_revoked_db_at
    BEFORE INSERT OR UPDATE OF status ON certificates
    FOR EACH ROW EXECUTE FUNCTION certificates_stamp_revoked_db_at();

CREATE INDEX idx_certs_revoked_db_at ON certificates(revoked_db_at) WHERE status = 'REVOKED';
```

## 8. Hackathon Live Demo Scope vs. Production Architecture

For the solo build, the Reactor Netty gateway, the admin plane, and the CA signing and revocation services run as
packages inside a single Spring Boot process, alongside PostgreSQL and **LocalStack KMS** in Docker Compose
(`http://localhost:4566`, configured via `LOCALSTACK_AUTH_TOKEN` in a gitignored `.env` file and placeholder SDK
credentials `test` / `test`). There is no internal Signer RPC and no per-service database role. LocalStack emulates the
AWS KMS API (`ECC_NIST_P256`, `kms:Sign`) with no AWS dependency during the demo, without the hardware key custody or
IAM isolation of production AWS KMS. The VPC subnet split, per-service PostgreSQL roles, multi-region KMS replicas,
the standby Intermediate, and a Keytos EZCA issuer remain the production design. Every listener binds loopback by
default (the admin listener always), and the admin plane is served as `http://localhost:8445` because an IP address
cannot be a WebAuthn RP ID; a page request to `127.0.0.1` is redirected there. `[D8, D25, D55, code]`

**Profiles.** The default profile is production-shaped (`leaf-ttl` `PT12H`, no hierarchy rebuild). `local` adds the
LocalStack endpoint, allows the rebuild, and uses `PT4M` leaves and a calibration window of 10. `demo` imports
`application-local.yml` and then `demo-stage.yml` (the later import wins): `leaf-ttl` `PT3M` (renewal due about 60 s
after issuance, expiry about 120 s after), `renewal-grace` `PT60S`, `calibration-size` 10, challenge limits 60 per
minute per address and 300 per minute globally, all traps on. Every rehearsal and the live run use `demo`;
`DemoProfileTest` checks the effective values. The simulator's compressed clock (Section 6) is disclosed here because it
changes what `measured_at` means on stage. `[D6, D74, D83, D88, D99]`

**Scope tiers.** The planning tiers put Protocol B as should-have and Protocol C and split-brain detection as
stretch, with `/challenge` live only if B or C was built. All three were built, so `/challenge` is live, and the
eviction backstop poller, which was to be marked Designed if not built, is live. `[D5, D13, D96]`

**Dashboard.** A Next.js static export served on the admin port from `vitalsshield.dashboard.dir` (default
`dashboard/out`). It polls the overview every 500 ms (chosen in Phase 5, when the admin API needed an `Authorization` header, which
EventSource cannot send),
shows serials in `openssl` hex, a DEV SEED badge, `needs_attention` flags, the clock skew tile, KMS health, and the
audit chain. The CSP allows no `'unsafe-inline'`: the server adds the SHA-256 hash of every inline script of the served
HTML file to `script-src`. Before Phase 6 the operator pasted the setup code (kept in `sessionStorage`); in the default
`webauthn` mode the dashboard uses the passkey session cookie. `npm audit` reports moderate advisories only in lint
tooling (0 in production dependencies), accepted for the hackathon. `[D47, D48, D50, D51, D52, D53, D77, D98]`

**Admin authentication modes.** `vitalsshield.admin.auth=webauthn` (default): the setup-code bearer only registers the
first clinician passkey (the dev seed passkey does not count), and every other admin call needs a passkey session,
with step-up for quarantine and restore. `bearer`: the Phase 5 behavior, with the setup code as the admin bearer token
(the fallback if WebAuthn had been cut). Phase 2 to 5 integration tests run in `bearer` mode; Phase 6 tests and the
e2e tier run in `webauthn` mode. `scripts/demo-cli.sh` defaults to UI quarantine. The dev seed tool (Section 4) is a
Gradle task on the test classpath, never an HTTP endpoint, and its devices show a DEV SEED badge. `[D32, D41, D60,
D64]`

**Test tiers.** `./gradlew test` runs unit tests only (no Docker). `integrationTest`, `e2eTest`, and `drillTest` run
tests tagged `integration`, `e2e`, and `drill`; they need Docker Compose and a LocalStack token, so CI
(`.github/workflows/ci.yml`) runs only the unit tier and the dashboard build. `drillTest` wipes the LocalStack keys and
is never run before a demo. In the table below, "Live (tested)" means an automated test in `server/src/test`,
`simulator/src/test`, or `crypto-common/src/test` exercises the behavior (in any tier); the claim-to-test map is kept
separately. `[D100, code]`

| Subsystem | Live (tested) | Live (manual verification) | Designed |
| :--- | :--- | :--- | :--- |
| **PKI and KMS signing** | Four P-256 KMS keys on LocalStack (Root, Device Intermediate, Server TLS CA, Registry Anchor) recorded in `kms_keys`; DIGEST signing; RFC 5280 profiles for Root, Device Intermediate, Server TLS CA, device leaf, and gateway leaf, checked with OpenSSL; first-boot build, second-boot no-op, local-profile rebuild on key loss (old issuers revoked, leaves revoked `HIERARCHY_REBUILD`, DEKs cleared); non-local profiles fail closed on a missing key; in-memory gateway TLS key, never on disk; boot steps in order with listeners last; KMS health monitor; canonical encodings against golden vectors. | A rebuild after a real LocalStack restart: `LocalStackRestartDrill` (drill tier, last run in Phase 4 and recorded in `docs/learning/phase-04-spine.md`; not part of the regular gate because it wipes the KMS keys). A rebuild after every `scripts/stage/01-reset.sh` before rehearsals (`Hierarchy reconciliation: REBUILT` in the server log). | AWS KMS HSM key custody; multi-region `mrk-*` replicas; offline Root ceremony role; Cold Standby Intermediate (KMS Key #3) and CA failover; Keytos EZCA `CertificateIssuer` implementation; a CRL for the Server TLS CA (D39); revocation metadata on `ca_issuers` (D22); Multi-AZ RDS. |
| **Process and privilege separation** | None: one process, one database user, one set of KMS credentials. | None. | CA Signer as a separate service with an internal mTLS RPC (no `/internal/v1/signer` endpoint exists; signing and revocation are in-process services); IAM role isolation (gateway with zero KMS permissions, signer role, ceremony role); DB role separation (`vitalsshield_gateway_role`, `vitalsshield_signer_role`, `vitalsshield_admin_role`); CloudWatch anomaly alarms on `kms:Sign`. |
| **Listeners, mTLS, and revocation enforcement** | Three listeners on loopback (8443 mTLS TLS 1.3 only, 8444 TLS 1.3, 8445 HTTP on `127.0.0.1` and `::1`); per-port path enforcement (404 elsewhere); trust manager (leaf only, PKIX against the current hierarchy, leaf policy, AKI pin, old-hierarchy leaves rejected, deny-list); no TLS resumption after session invalidation; post-handshake gate; uncached per-request status check; live socket eviction under 500 ms; deny-list survives restart; 30 s deny-list refresh; backstop poller on `revoked_db_at`; CRLs cached, never signed by a GET, republished after revocation and coalesced. | TLS alert 46 for a revoked client certificate, observed in OpenSSL `s_client` output (printed by the resumption test run, not asserted) and reasoned from the JDK 21 source (D37); quarantine latency 8.7 ms in the scripted stage rehearsal. | Redis pub/sub eviction broadcast between gateways; L4 TCP passthrough load balancer; CRL publication to object storage behind a CDN and rate limiting on 8444 (D29, D30); TLS in front of the admin plane. |
| **Enrollment (Protocol A) and provisioning** | Provisioning begin/finish with the `ProvisioningDigest` challenge; token claim, reclaim after 2 minutes, burn on proof failure, return on transient failure, 503 with `Retry-After` for enrollment; DEK proof, CSR proof, KMS Key #4 DEK anchor; re-verification of the stored assertion (D3; SQL-forged tokens refused with `PROVISIONING_UNVERIFIED`); boot epoch 1 for a first-time device and +1 on re-provision; serial reservation ledger with voiding and `REPLACED_BEFORE_USE`; simulator enroll and persistence; dev seed tool restrictions. | A Touch ID provisioning approval that passed Protocol A re-verification (`dev_touchid_001`, boot epoch 1) (D80). | Hardware-backed DEK generation in a secure element. |
| **WebAuthn admin plane** | With a software authenticator: passkey registration with the setup code (first passkey only), discoverable sign-in, sessions (idle and absolute limits), SameSite=Strict cookie and Origin check, 307 from `127.0.0.1` to `localhost`, KMS Key #4 passkey anchor checked before every assertion, signature counter rule, ceremony expiry and single use (410, D65), action-bound step-up for quarantine and restore with server-held parameters, dev seed passkey refused for sign-in and step-up. | Real Touch ID (Secure Enclave, iCloud Keychain, Chrome) for registration with the setup code, provisioning, and step-up quarantine (2026-11-16). Discoverable sign-in after sign-out, the token disappearing after reload, and repeat sign-in with sign count 0 were run only with a DevTools virtual authenticator in headless Chrome; manual confirmation with real Touch ID is pending (D80). | WebAuthn attestation verification (attestation is `none`, D63); shared or persistent admin sessions and ceremonies. |
| **Telemetry and replay window** | JWS ES256 verification with the TLS certificate's key only, header allow-list, certificate binding, strict payload; the v1 replay CTE checked against a model over 2000 random operations; concurrent duplicates; idempotent retries; `BATCH_ID_REUSED`; `ASSIGNMENT_CHANGED`. | None beyond the tests. | Hardware flash ring buffer with FIFO drain (D44: the simulator retries one frame instead); a 503 with `Retry-After` on the ingest path. |
| **Renewal (Protocol B)** | Renew challenge bound to the TLS certificate's serial; body binding; proof checks; nonce replay refused; first-use activation; concurrent activation; grace, scheduled grace eviction, and per-request refusal after grace; lost response leading to `REPLACED_BEFORE_USE`; renewal on `ASSIGNMENT_CHANGED`; quarantine during renewal; crash after sign voided by the sweep and listed; expiry sweep (including the boot run); simulator renewal due rule and pending-certificate store. | Automatic rollovers in the scripted stage rehearsal with `PT3M` leaves (`scripts/rehearsal/rehearse.mjs`, headless Chrome; not part of the test suite). | None. |
| **Re-enrollment (Protocol C) and split-brain detection** | Re-enroll challenge (stateless HMAC, separate key); rate limiter (unit test); offline-expiry recovery keeping epoch and sequence; mid-stream recovery resending the same frame; epoch rules (`INVALID`, `REGRESSION`, restore then `RESYNC`); forged DEK refused; collision rule (expired certificate never collides); sequence-regression trap; post-drain trap; anomaly response; normal operation with all traps on raises no anomaly. | Offline-expiry drill and two-copy clone drill run by hand with the simulator (Phase 9 notes); clone drill, restore, and re-enrollment at boot epoch 2 in the scripted stage rehearsal (virtual authenticator for the restore step-up). | A trap on "renewal attempted from a certificate whose successor was issued to a different key" (D102); shared rate limits across gateways (Redis). |
| **Clinical engine, quarantine, and retraction** | Plausibility and perfusion classification; activity context with the 5-minute resting rule; acute alerts with dedupe; low-perfusion critical streak; calibration with sample SD and floors; drift alerts with lineage; streak restart on untrusted evidence; evaluation queue cap and counters; alert acknowledge and resolve with audit; lock-then-sanitize quarantine with no `ACCEPTED` row surviving a concurrent ingest; dual-timestamp sanitize, baseline reset, scoped retraction (including in-flight evaluations); global lock order with no deadlock under mixed load; quarantine and audit atomic. | Touch ID step-up quarantine refusing the device's reconnect at the handshake (D80). | Durable clinical evaluation outbox (D79); paging or escalation for alerts; clinical validation of every threshold. |
| **Audit chain** | Hash chain under the advisory lock, chain verification, append-only triggers, audit atomic with each action. | Audit panel "chain valid" in the manual Touch ID run and in the scripted stage rehearsal. | S3 Object Lock (`COMPLIANCE` mode) anchoring of the chain head signed by KMS Key #4 (D62). |
| **Clock discipline** | Same-clock rule for every comparison fixed in Phase 9 (JVM clock 10 minutes behind Postgres); skew classification green/amber/red; overview reports both clocks. | The pre-stage script (`scripts/stage/00-prestage.sh`) fails unless the skew tile is green; the Phase 8 soak run observed a 13.6 s skew after a laptop sleep (D98). | None. |
| **Dashboard and demo operations** | Static serving on the admin port, path-traversal refusal, CSP with inline-script hashes; overview API including `needs_attention`, `CERT_EXPIRED_NO_SUCCESSOR`, and clock skew; demo profile effective values. | Nine-beat scripted stage rehearsal in headless Chrome at 1440x900 with a virtual authenticator (1:52, 2026-11-20; a script, not part of the test suite); full-history secret scan before publication (one finding: two consumed Phase 3 dev-seed bootstrap tokens in the history of a learning note, redacted in the current tree, history not rewritten) (D101). | None. |

## 9. Residual risks (new)

These are the risks that remain in the system as built. Each is either inherent to the design or deferred to a
Designed item in Section 8.

| Risk | Where | Why it remains | What bounds it today |
| :--- | :--- | :--- | :--- |
| **Offline clone window** | Section 2, layer 5 | A clone that copies the DEK and re-enrolls while the legitimate device is off or offline sees no live socket and no recent ingest, so it looks like a normal offline recovery. The traps need a conflict; two copies that never overlap look like one device. | When the real device returns, its old certificate is refused (the clone's re-enrollment revoked it). If its leaf has expired it runs Protocol C, and the collision check fires while the clone is streaming; if both copies stream at once, the sequence-regression trap fires. A real device that is refused and does not re-enroll raises no anomaly, though its refusals are visible. `max_renewal_horizon` and clinician quarantine bound the rest. `[D91, D93, D95]` |
| **Renewal-race clone** | Section 2, layer 5; Section 4 | A clone copied shortly before a scheduled renewal can renew first. The real device's pending certificate is then revoked as `REPLACED_BEFORE_USE`, which looks like a lost renewal response. A real device that falls back to its old certificate after grace trips the post-drain trap; the simulator instead exits 3. A trap on "renewal attempted from a certificate whose successor was issued to a different key" is Designed (feature freeze). | Visible renewal failures on the real device; post-drain trap for a real device that keeps using its old certificate. `[D94, D102]` |
| **Software DEK** | Section 2, layer 4 | Without a secure element the DEK is a file (`keys/dek.key`, mode 600 in the simulator). Anyone who can read it can re-enroll as the device. | `max_renewal_horizon` (30 days by default); the clone traps when copies overlap; quarantine clears the DEK. `[D95]` |
| **Rooted device signing false values** | Section 2, layer 2 | JWS proves which key signed a batch, not that the numbers are true. A compromised device can send plausible, well-signed readings and build a false baseline. | Detection and clinician quarantine, which retracts what was built on the quarantined window; data outside the lookback window stays trusted. |
| **Clinical thresholds not validated** | Section 6 | Plausibility bounds, acute limits, z-score thresholds, SD floors, and calibration size are engineering defaults, not clinically validated. | They are configuration (`vitalsshield.clinical.*`); the engine does not replace clinical judgment. `[D72]` |
| **Trap thresholds not measured** | Sections 2 and 4 | 3 rejections in 60 s and 5 s after grace were chosen for the demo. They have not been measured against real multi-gateway reordering, which could produce occasional `DUPLICATE_SEQUENCE_REPLAY` rejections. | One rejection never fires the trap; idempotent retries never count; `NormalOperationNoAnomalyE2E` shows no false positive in normal single-gateway operation. `[D93, D94, D100]` |
| **Admin plane without TLS** | Sections 1 and 8 | Port 8445 is plain HTTP on loopback (`127.0.0.1` and `::1`). Any process on the machine that can read loopback traffic can read the session cookie (which has no `Secure` flag). | Loopback binding; SameSite=Strict, HttpOnly, Origin check; quarantine, restore, and provisioning each need a fresh user-verified passkey assertion, so a stolen session can browse but not act. `[D55, D59]` |
| **In-memory admin sessions and ceremonies** | Section 1 | `AdminSessionStore` and `CeremonyStore` live in memory. A restart signs every clinician out and drops ceremonies in progress (including a provisioning ceremony's plaintext token before finish); they are not shared between processes. | A nuisance, not a bypass: a lost ceremony is 410 and is started again. `[D59, D65]` |
| **In-memory grace-eviction timers** | Section 4 | The timer that closes a `RENEWED` certificate's sockets at the end of grace is held in memory in the process that activated the successor. Another gateway process would have no timer. | A restart drops every socket anyway, the reseeded deny-list refuses the old certificate after grace, and the per-request check refuses every request on a socket kept open past grace. `[D84]` |
| **Per-process rate limits and counters** | Section 4 | The challenge rate limiter, the sequence-regression counts, and the post-drain queue are per process and in memory, and the limiter keys on the TCP peer address (behind a proxy, every client shares one address). | One process in the build; shared limits over Redis are Designed. `[D90, D93, D94]` |
| **Single process holds every key** | Sections 2 and 3 | A compromise of the server process can call `kms:Sign` on all four keys and write every table. | Designed separation (Section 8); KMS keeps the private keys non-exportable, so a compromise lasts only while the attacker controls the process. |
| **Audit chain not anchored** | Section 7 | Without S3 Object Lock, a database superuser can drop the triggers and rewrite the chain consistently. | Append-only triggers stop edits through normal roles; the chain detects partial edits. `[D62, D75]` |
| **Lost clinical evaluations** | Section 6 | Queue overflow and a crash leave accepted batches unevaluated; they are never replayed. | Counted on the dashboard; durable outbox Designed. `[D79]` |

## Appendix A: Decision index

One line per row of `docs/DECISIONS.md`: number, short title, and the v2 section(s) that fold it in.

| # | Title | Sections |
| :--- | :--- | :--- |
| 1 | Quarantine scope and order | §4, §6 |
| 2 | Server TLS Issuing CA for the gateway | Positioning, §3 |
| 3 | Protocol A DEK anchor and approval re-verification live | §2, §4, §8 |
| 4 | Admin API routes | §4, §7 |
| 5 | Scope tiers for Protocols B and C (all built) | §8 |
| 6 | Demo clock compression and calibration window | §6, §8 |
| 7 | Column name dek_spki_der_b64 | §2, §3, §7 |
| 8 | Redis broadcast Designed (single process) | §1, §3, §4, §8 |
| 9 | Nullable WebAuthn token columns if cut (not needed) | §7 |
| 10 | Provisioning begin/finish, digest as challenge | §3, §4 |
| 11 | Revocation latency definition and 500 ms bound | §2, §4, §5 |
| 12 | Local reconciliation all-or-nothing | §3, §4 |
| 13 | Backstop poller marking (built, see 96) | §4, §8 |
| 14 | kms_keys table, ACTIVE rows only | Positioning, §3, §7 |
| 15 | Ephemeral in-memory gateway TLS key | §3 |
| 16 | Boot order | §3 |
| 17 | KMS DIGEST signing | §3 |
| 18 | SKI as SHA-256 of SPKI | §3 |
| 19 | Revocation reasons to CRLReason | §3, §7 |
| 20 | Rebuild keeps quarantine trust states | §3, §4 |
| 21 | Protocol C nonce fixed at 16 bytes | §3, §4 |
| 22 | ca_issuers lacks revocation metadata | §4, §7, §8 |
| 23 | No CertStatusResolver cache | Positioning, §2, §4, §5 |
| 24 | Handshake deny-list and post-handshake gate | Positioning, §2, §4 |
| 25 | Loopback binding | §1, §8 |
| 26 | TLS resumption prevented by session invalidation | Positioning, §1, §2, §4 |
| 27 | CRLs cached and republished, GET never signs | §3, §4 |
| 28 | 30 s deny-list refresh as handshake backstop | §3, §4 |
| 29 | CRL endpoint not rate limited | §4, §8 |
| 30 | Per-process CRL cache | §4, §8 |
| 31 | First-time device keeps boot_epoch 1 | §4 |
| 32 | Dev seed tool | §4, §8 |
| 33 | DER signatures outside JWS | §3, §4 |
| 34 | Enrollment token semantics | §4 |
| 35 | Thumbprint column equals x5t#S256 | §2, §4, §5, §7 |
| 36 | Simulator uses 127.0.0.1 with hostname verification | §3, §4 |
| 37 | Alert 46 for rejected client certificates | §2, §8 |
| 38 | Serial reservation ledger | §3, §4, §7 |
| 39 | Gateway leaves untracked, no Server TLS CA CRL | §3, §7, §8 |
| 40 | Sequence numbers start at 1 | §2, §5 |
| 41 | Setup code as admin bearer | §3, §4, §8 |
| 42 | Lock and flip state before sanitize | Positioning, §6 |
| 43 | JWS header policy | §2, §5 |
| 44 | Simulator retries the same frame | §4, §5, §8 |
| 45 | Quarantine revokes outstanding tokens | §4, §6 |
| 46 | Ingest classification by plausibility and perfusion | §5, §6 |
| 47 | Dashboard static export on the admin port | §8 |
| 48 | Dashboard polls every 500 ms | §8 |
| 49 | KMS health monitor never rebuilds | §3, §4 |
| 50 | Serial display format | §3, §8 |
| 51 | DEV SEED badge | §4, §8 |
| 52 | CSP inline-script hashes | §8 |
| 53 | npm audit advisories accepted | §8 |
| 54 | WebAuthn library and Jackson isolation | §1 |
| 55 | Admin plane at http://localhost:8445 | §1, §8, §9 |
| 56 | Passkey registry anchor live | §2, §3 |
| 57 | Protocol A re-verifies the stored assertion | §1, §2, §4 |
| 58 | Action-bound step-up approvals | §2, §3, §4 |
| 59 | Admin session cookie and Origin check | §1, §9 |
| 60 | Setup code only for the first passkey | §1, §2, §4, §8 |
| 61 | Signature counter rule | §1 |
| 62 | Audit hash chain; S3 anchoring Designed | §7, §8, §9 |
| 63 | Attestation none | §1, §8 |
| 64 | Dev seed passkey not counted; test auth modes | §1, §4, §8 |
| 65 | Ceremony keys, 410, refusal without CRL republish | §4, §8, §9 |
| 66 | Dev seed passkey restricted by purpose | §1, §2, §4, §7 |
| 67 | Audit atomic with its action; audit lock last | §6, §7 |
| 68 | V5 clinical columns | §6, §7 |
| 69 | Evaluation after commit, ingestion order | §6 |
| 70 | Global lock order and FOR NO KEY UPDATE | §4, §6 |
| 71 | Alert dedupe | §6 |
| 72 | Calibration statistics and SD floors | §6, §9 |
| 73 | Drift streak counting | §6 |
| 74 | Simulator persisted compressed clock | §6, §8 |
| 75 | Audit append-only trigger | §7, §9 |
| 76 | Alert acknowledge and resolve | §6, §7 |
| 77 | needs_attention flag | §6, §8 |
| 78 | Streak restart on untrusted evidence | §1, §6 |
| 79 | Clinical evaluation queue cap; outbox Designed | §6, §8, §9 |
| 80 | Manual Touch ID verification | §1, §8 |
| 81 | Protocol B binding and per-boot HMAC key | §4 |
| 82 | Lock order gains certificates | §4, §6 |
| 83 | Renewal at 2/3; demo and local TTLs | §2, §3, §4, §8 |
| 84 | Grace eviction and expiry sweep | §1, §3, §4, §7, §9 |
| 85 | Simulator pending-certificate crash safety | §1, §4 |
| 86 | Renew on ASSIGNMENT_CHANGED | §4 |
| 87 | Expiry sweep scope, JVM clock, boot run | §3, §4, §5 |
| 88 | Compressed clock and laptop sleep | §6, §8 |
| 89 | Same-clock rule | §3, §4, §5, §6, §7 |
| 90 | Re-enroll challenge endpoint and rate limits | §4, §9 |
| 91 | Collision rule | §1, §2, §4, §9 |
| 92 | Anomaly response | Positioning, §1, §2, §4, §7 |
| 93 | Sequence-regression trap | §1, §2, §4, §5, §9 |
| 94 | Post-drain trap | §1, §2, §3, §4, §9 |
| 95 | Simulator Protocol C automation and exit codes | §2, §4, §9 |
| 96 | Eviction backstop poller on revoked_db_at | §3, §4, §7, §8 |
| 97 | Same epoch keeps the replay window | §2, §4 |
| 98 | Clock-skew monitor | §3, §4, §5, §8 |
| 99 | Demo profile | §2, §3, §4, §8 |
| 100 | NormalOperationNoAnomalyE2E in the gate | §2, §8, §9 |
| 101 | Release secret scan | §8 |
| 102 | Renewal-race clone residual risk | §2, §4, §8, §9 |
