# VitalsShield: Technical Architecture and System Design Specification

**Positioning Statement:**

*VitalsShield establishes cryptographic device provenance for wearable telemetry using an AWS KMS-backed CA hierarchy and per-batch JWS origin authentication, enforces real-time connection and payload authorization over Reactor Netty, and isolates revoked or degraded data sources from contaminating preventive health baselines.*

## 1. Key Design Decisions

| Architectural Pillar | Core Mechanism | Engineering Rationale |
| :--- | :--- | :--- |
| **Multi-Port Listener Isolation** | Reactor Netty separates Port `8443` (`ClientAuth.REQUIRE`, resumption disabled), Port `8444` (public enrollment/CRL), and Port `8445` (private VPC/localhost WebAuthn admin plane) behind L4 TCP passthrough. | Prevents mTLS chicken-and-egg lockouts during enrollment while preserving gateway ownership of raw client `io.netty.channel.Channel` handles for immediate socket eviction. |
| **Internal CA Signer Isolation** | Public gateways hold zero AWS KMS permissions and cannot write to PKI tables; all issuance and revocation requests carry device-signed proofs verified by an isolated CA Signer Service. | Ensures a compromised DMZ gateway cannot mint rogue certificates or forge enrollment claims for arbitrary devices. |
| **First-Use Certificate Activation** | Renewed certificates enter `ISSUED_PENDING_USE` while the prior certificate remains `ACTIVE`, switching over only when the new certificate transmits its first valid batch. | Prevents dropped HTTP responses over flaky wireless links from stranding wearables on an expiring drain timer. |
| **Non-Destructive Anomaly Handling** | Suspected key clones or sequence regressions revoke the active transport certificate (`REAUTH_REQUIRED`) and raise a security alert without automatically purging historical vitals. | Avoids destroying patient data on a false positive; retroactive data quarantine requires explicit clinician WebAuthn approval. |
| **Lineage-Tracked Alert Retraction** | Clinical alerts store `triggering_batch_ids` and (for drift alerts) `baseline_version`, automatically retracting tainted alerts when lookback data is quarantined. | Prevents compromised sensor batches from corrupting locked reference baselines or leaving stale alerts in the clinician queue. |

## 2. Security Boundaries and Threat Model

| Security Layer | Mechanism | What It Proves | Explicit Limitation and Residual Risk |
| :--- | :--- | :--- | :--- |
| **1. Transport Authentication** | Mutual TLS 1.3 on Reactor Netty (Port `8443`, session resumption disabled) | The peer holds the private key for the presented X.509 operational leaf certificate on every TCP connection. | Requires per-request status verification and Netty `Channel.close()` to terminate established keep-alive connections upon revocation. |
| **2. Origin Authentication and At-Rest Integrity** | RFC 7515 JWS (`ES256`) with `x5t#S256` binding | The telemetry batch was signed by the operational leaf key corresponding to the authenticated TLS client certificate and remains verifiable at rest. | Provides cryptographic **origin authentication**; if wearable firmware is rooted, the attacker can sign falsified sensor values. |
| **3. Provisioning and Registry Integrity** | KMS-Anchored Clinician Passkey -> Provisioning Assertion -> KMS Key #4 DEK Anchor | Neither `clinician_passkeys` nor `devices.dek_spki_der` can be forged via runtime SQL modification without access to KMS Key #4. | Compromising the internal CA Signer Service allows calling `kms:Sign` on Key #2/#4 until CloudWatch anomaly alarms revoke the IAM session. |
| **4. Device Credential Hierarchy** | Long-lived DEK (re-enrollment) + 12-hour OLK (mTLS/JWS, renewed at 8h) | Limits active transport key exposure and enforces periodic authorization checks against `max_renewal_horizon`. | Without a hardware Secure Element (e.g., ATECC608), the DEK is a software key; extracting it allows re-enrollment when the legitimate device is idle/offline until `max_renewal_horizon` expires. |
| **5. Split-Brain Anomaly Detection** | Epoch-agnostic active-session collision + post-drain and sequence-regression traps | Detects concurrent transmission from a cloned keypair and transitions the device to `REAUTH_REQUIRED`. | If a legitimate device powers off or loses connectivity immediately before an attacker uses a cloned DEK to re-enroll, the takeover resembles a normal offline recovery until the legitimate device reconnects and triggers a collision. |
| **6. Replay and Ordering Defense** | Single-CTE atomic 64-bit sliding bitmap keyed by `(device_id, boot_epoch, sequence_number)` | Absorbs minor L4 multi-gateway packet reordering while rejecting duplicate replays and distinguishing idempotent network retries. | Wearables must drain buffered offline frames in FIFO order before transmitting live measurements. |

## 3. Two-Tier AWS KMS PKI, Signer Isolation, and RFC 5280 Profiles

### Key Custody, DB Role Separation, and Signer Isolation

Both the Root CA and Intermediate CA private keys reside inside non-exportable **AWS KMS** `ECC_NIST_P256` keys (`KeyUsage: SIGN_VERIFY`). The certificate issuer sits behind an internal `CertificateIssuer` interface, making Keytos EZCA a drop-in replacement for the AWS KMS signer. Separating the public ingestion gateway from an internal CA Signer Service ensures an RCE in the DMZ gateway cannot invoke `kms:Sign` or mutate PKI tables:

```text
+----------------------------------------------------------------------------+
|          OFFLINE CEREMONY PLANE (Restricted to Ceremony IAM Role)          |
|  IAM Role: VitalsShieldRootCaCeremonyRole (Hardware MFA Required)          |
|  - AWS KMS Key #1 (Root CA, ECC_NIST_P256): Signs Intermediate CAs (#2, #3)|
|    and signs Root CRL every 90 days (180-day nextUpdate validity).         |
+-------------------------------------+--------------------------------------+
                                      |
                                      v
+----------------------------------------------------------------------------+
|          ADMIN CONTROL PLANE (Port 8445: localhost / Internal DNS)         |
|  DB Role: vitalsshield_admin_role (statement_timeout = '5s')               |
|  - Enforces FIDO2 / WebAuthn passkey authentication (RP ID: localhost or   |
|    admin.vitalsshield.internal).                                           |
|  - Forwards signed provisioning and quarantine assertions to Signer RPC.   |
+-------------------------------------+--------------------------------------+
                                      |
                                      v
+----------------------------------------------------------------------------+
|          INTERNAL CA SIGNER SERVICE (Private Subnet RPC)                   |
|  IAM Role: VitalsShieldCaSignerRole | DB Role: vitalsshield_signer_role    |
|  - AWS KMS Key #2 (Active Intermediate CA, Multi-Region mrk-*, P-256)      |
|  - AWS KMS Key #3 (Cold Standby Intermediate CA, Multi-Region mrk-*, P-256)|
|  - AWS KMS Key #4 (Registry and Audit Anchor Key, Multi-Region mrk-*, P-256)|
|  - Sole writer to certificates, device_bootstrap_tokens, clinician_passkeys|
|    and devices.dek_* / trust_state columns. Exposes internal RPCs for      |
|    enrollment, OLK-verified renewal, DEK re-enrollment, and revocation.    |
+-------------------------------------+--------------------------------------+
                                      ^
                                      | Internal mTLS RPC (Raw client-signed payloads)
+-------------------------------------+--------------------------------------+
|          PUBLIC REACTOR NETTY GATEWAY (DMZ: Ports 8443 and 8444)           |
|  IAM Role: VitalsShieldGatewayRole (ZERO KMS permissions)                  |
|  DB Role: vitalsshield_gateway_role (SELECT on PKI tables; INSERT/UPDATE   |
|  ONLY on telemetry_records, clinical_alerts, and devices replay counters). |
+----------------------------------------------------------------------------+
```

**Local KMS Profile (LocalStack):** For local development and the hackathon demo, `KmsClient` accepts an endpoint override (`vitalsshield.kms.endpoint=http://localhost:4566`) with an explicit region (`us-east-1`) and placeholder credentials (`test` / `test`), targeting LocalStack in Docker Compose. The container reads `LOCALSTACK_AUTH_TOKEN` from a gitignored `.env` file. LocalStack reproduces the KMS API (`ECC_NIST_P256`, `ECDSA_SHA_256`) but not HSM key custody or IAM isolation. Because a container restart can clear KMS state, the **local profile only** runs an idempotent startup check: if the key IDs referenced by `ca_issuers` no longer exist, it creates new keys through the SDK (`CreateKey`), builds a fresh Root and Intermediate hierarchy, reloads the gateway trust store, and revokes all leaf certificates issued under the old hierarchy so devices re-enroll. The production profile never regenerates CA keys; a missing key fails startup closed and pages an operator.

### Canonical Binary Encodings

All multi-field cryptographic signatures use explicit big-endian length prefixes (`uint32_be`) or fixed-width digests so fields cannot be shifted across boundaries:

1. **Clinician Passkey Anchor (`passkey_registry_kms_sig`, signed by KMS Key #4):**
   `PasskeyAnchorBytes = uint32_be(len(cred_id)) || utf8(cred_id) || uint32_be(len(clinician_id)) || utf8(clinician_id) || sha256(cose_pub_key_der)`

2. **Clinician WebAuthn Provisioning Commitment (`ProvisioningDigest`):**
   `ProvisioningDigest = SHA256(uint32_be(len(device_id)) || utf8(device_id) || sha256(bootstrap_token_ascii) || int64_be(expires_at_epoch_ms))`

3. **Enrollment DEK Proof-of-Possession (`dek_proof_sig`, signed by Device `DEK`):**
   `DekEnrollmentProofBytes = uint32_be(len(device_id)) || utf8(device_id) || sha256(bootstrap_token_ascii) || sha256(olk_csr_der)`

4. **DEK Registry Anchor (`dek_registry_kms_sig`, signed by KMS Key #4):**
   `DekAnchorBytes = uint32_be(len(device_id)) || utf8(device_id) || sha256(dek_spki_der) || int64_be(provisioned_at_epoch_ms)`

5. **OLK Renewal Proof (`olk_renewal_sig`, signed by Current `OLK`):**
   `OlkRenewalProofBytes = uint32_be(len(issuer_key_hash)) || utf8(issuer_key_hash) || uint32_be(len(serial_number)) || utf8(serial_number) || int64_be(issued_at_ms) || random_nonce (16B) || sha256(olk_new_csr_der)`

### Explicit RFC 5280 X.509v3 Certificate Profiles

The CA Signer Service ignores all Subject, SAN, and extension attributes inside the client's PKCS#10 CSR, using the CSR solely to extract the candidate `SubjectPublicKeyInfo` and verify its Proof-of-Possession signature.

| Field / Extension | Root CA Profile | Issuing Intermediate CA Profile | Wearable Operational Leaf Profile |
| :--- | :--- | :--- | :--- |
| **Signature Algorithm** | `SHA256withECDSA` (KMS Key #1) | `SHA256withECDSA` (Signed by KMS Key #1) | `SHA256withECDSA` (Signed by Multi-Region KMS Key #2) |
| **Subject DN** | `CN=VitalsShield Root CA, O=VitalsShield` | `CN=VitalsShield Issuing CA G1, O=VitalsShield` | `CN=<device_id>, O=VitalsShield Devices` |
| **Validity Period** | 10 Years | 1 Year | **12 Hours** (`PT12H`, renewed at `PT8H`) |
| **Basic Constraints** | `critical, CA:TRUE, pathLenConstraint:1` | `critical, CA:TRUE, pathLenConstraint:0` | `critical, CA:FALSE` |
| **Key Usage (`KU`)** | `critical, keyCertSign, cRLSign` | `critical, keyCertSign, cRLSign` | `critical, digitalSignature` |
| **Extended Key Usage (`EKU`)** | *Omitted* | `id-kp-clientAuth` (Non-critical; enforced by gateway `TrustManager`) | `critical, id-kp-clientAuth` (`1.3.6.1.5.5.7.3.2`) |
| **Subject Key Identifier (`SKI`)** | SHA-256 of Root SPKI DER | SHA-256 of Intermediate SPKI DER | SHA-256 of Leaf SPKI DER |
| **Authority Key Identifier (`AKI`)** | *Omitted on self-signed root* | Root `SKI` (`issuer_key_hash`) | Intermediate `SKI` (`issuer_key_hash`) |
| **Subject Alternative Name (`SAN`)** | *Omitted* | *Omitted* | **Non-critical** (per RFC 5280 §4.2.1.6), `URI:urn:vitalsshield:device:<device_id>` |
| **CRL Distribution Points** | *Omitted on self-signed root* | `https://<host>:8444/api/v1/pki/root-crl.pem` (`nextUpdate` = 180d, refreshed every 90d) | `https://<host>:8444/api/v1/pki/intermediate-crl.pem` (`nextUpdate` = 24h) |

## 4. Enrollment, First-Use Renewal, and Split-Brain Recovery

### Wearable Persistence and Reboot Semantics

Wearables persist their active `OLK` keypair, operational X.509 certificate, `boot_epoch`, and `sequence_number` in non-volatile flash across normal power cycles. Consequently, a routine reboot reconnects directly over Port `8443` mTLS using its existing certificate and continuing `sequence_number` without triggering `/re-enroll` or false-positive clone alerts. `/re-enroll` on Port `8444` is invoked only when the 12-hour operational certificate expires while offline, after an Intermediate CA failover, or after a reset of the device's state partition. The DEK is stored in a separate key partition that survives a state reset, so a device that loses only its `boot_epoch` and `sequence_number` can still prove its identity and recover through clinician `/restore-active` plus `/re-enroll`. A full factory wipe that erases the DEK cannot re-enroll; the clinician must re-provision the device through Protocol A with a new bootstrap token, which replaces the stored DEK and its `dek_registry_kms_sig`.

### Certificate Lifecycle State Machine (First-Use Switchover)

Both `DynamicMtlsTrustManager` (TLS handshake) and `CertStatusResolver` (per-request telemetry filter) accept certificates in `ACTIVE` or `ISSUED_PENDING_USE` status, or in `RENEWED` status while `NOW() < grace_expires_at`, provided `NOW()` is within `[not_before, not_after)`:

```text
                      [POST /api/v1/devices/renew]
                                   |
                                   v
                        ISSUED_PENDING_USE
        (Accepted by TrustManager and per-request filter; old cert
         remains ACTIVE so retrying /renew is idempotent)
                                   |
        First valid telemetry batch arrives signed by new cert
                                   |
                                   v
                                ACTIVE
        (Old cert atomically transitions to RENEWED with
         grace_expires_at = NOW() + 60s to drain in-flight packets)
                                   |
               +-------------------+-------------------+
               |                                       |
               v                                       v
            RENEWED                                 REVOKED
   (Valid until grace_expires_at,            (Terminal: Socket closed
    then rejected as superseded)              immediately via Netty)
```

### Protocol A: WebAuthn-Anchored Bootstrap Enrollment (Port `8444`, `POST /api/v1/devices/enroll`)

1. Wearable submits `{device_id, bootstrap_token, dek_spki_der_b64, olk_csr_der_b64, dek_proof_sig}` to Port `8444`, which forwards the raw request to the CA Signer Service.

2. **Short Tx 1:** CA Signer atomically claims the `device_bootstrap_tokens` row (`status = 'CLAIMING'`) and loads the clinician's passkey (`clinician_passkeys`) and WebAuthn assertion.

3. **Out-of-Tx Verification and KMS Signing:**

   * Verifies `passkey_registry_kms_sig` (using KMS Key #4 public key) and verifies the clinician's WebAuthn signature over `ProvisioningDigest`.

   * Verifies `dek_proof_sig` over `DekEnrollmentProofBytes` and verifies the `OLK` CSR signature.

   * Calls `kms:Sign` on KMS Key #4 to produce `dek_registry_kms_sig` over `DekAnchorBytes`, and calls `kms:Sign` on KMS Key #2 to sign the initial 12-hour leaf certificate (`status = 'ACTIVE'`).

4. **Short Tx 2:** Revokes any prior certificates for `device_id` (`SUPERSEDED_BY_REPROVISION`), persists `dek_*` columns on `devices` (`trust_state = 'ACTIVE'`), inserts the `ACTIVE` certificate, and marks the token `'CONSUMED'`. A first-time device receives `boot_epoch = 1`; a re-provisioned device receives `boot_epoch = devices.boot_epoch + 1` with `last_sequence_num = 0` and `replay_bitmap = 0`, so new batches never collide with historical sequence numbers. The response returns `{new_cert_pem, assigned_boot_epoch, current_assignment_id, assignment_active_from}`.

### Protocol B: OLK-Signed, First-Use-Activated Renewal (Port `8443` mTLS, `POST /api/v1/devices/renew`)

Triggered at **8 hours** (or immediately upon receiving `409 ASSIGNMENT_CHANGED`):

1. Wearable fetches a stateless HMAC challenge (`{issued_at_ms, random_nonce_b64, hmac_tag_b64}`) and submits `{issuer_key_hash, serial_number, issued_at_ms, random_nonce_b64, hmac_tag_b64, olk_new_csr_der_b64, olk_renewal_sig}` over Port `8443`.

2. **Signer Verification:**

   * Verifies `hmac_tag_b64` and `abs(now_ms - issued_at_ms) <= 60000`.

   * Fetches the `ACTIVE` certificate for `(issuer_key_hash, serial_number)` from PostgreSQL, verifies `NOW() < cert.not_after`, and cryptographically verifies `olk_renewal_sig` over `OlkRenewalProofBytes` using the stored certificate's public key.

   * Inserts `random_nonce_b64` into `consumed_challenge_nonces`.

   * Verifies `devices.trust_state == 'ACTIVE'` and requires an `ACTIVE` `PatientDeviceAssignment` with `NOW() < assignment.max_renewal_horizon` (if no active assignment exists, returns `409 DEVICE_UNASSIGNED`).

3. **Idempotent Pending Issuance:**

   * Any prior unused `ISSUED_PENDING_USE` certificate for `device_id` is marked `REVOKED (REPLACED_BEFORE_USE)`.

   * The newly signed 12-hour certificate is inserted with `status = 'ISSUED_PENDING_USE'` and `superseded_serial = serial_number`, while the presenting certificate remains `ACTIVE`.

   * Returns `{new_cert_pem, current_assignment_id, assignment_active_from}`.

4. **Switchover on First Telemetry Batch:** When the wearable sends its first valid JWS batch signed with the `ISSUED_PENDING_USE` certificate, the ingestion pipeline calls the Signer RPC to transition the new certificate to `ACTIVE` and transition `superseded_serial` to `RENEWED` (`grace_expires_at = NOW() + INTERVAL '60 seconds'`).

### Protocol C: Challenge-Response Offline Re-Enrollment (Port `8444`, `/challenge` and `/re-enroll`)

1. Wearable obtains a stateless HMAC challenge from `/api/v1/devices/challenge` (rate-limited by IP/globally; zero DB writes).

2. Wearable submits `{device_id, issued_at_ms, random_nonce_b64, hmac_tag_b64, boot_epoch, olk_csr_der_b64, dek_sig}` signing `(uint32_be(len(device_id)) || utf8(device_id) || int64_be(issued_at_ms) || random_nonce || int64_be(boot_epoch) || sha256(olk_csr_der))` with its `DEK`.

3. **Signer Verification and State-Reset Epoch Resync:**

   * Verifies `hmac_tag_b64`, verifies `dek_registry_kms_sig` on `devices`, and verifies `dek_sig` against `devices.dek_spki_der`.

   * Inserts `random_nonce_b64` into `consumed_challenge_nonces`.

   * Checks `devices.trust_state == 'ACTIVE'` and requires an `ACTIVE` `PatientDeviceAssignment` with `NOW() < max_renewal_horizon`.

   * **Epoch Handling:**

     * `boot_epoch` is server-assigned. Wearables always present the last epoch they received and never increment it themselves. Any presented value greater than `devices.boot_epoch` is rejected with `409 BOOT_EPOCH_INVALID` and triggers `REAUTH_REQUIRED`.

     * If `devices.epoch_resync_allowed == TRUE` (set by clinician `/restore-active` for a state-reset device) and `boot_epoch <= devices.boot_epoch`, the server assigns `assigned_boot_epoch = devices.boot_epoch + 1`, resets `last_sequence_num = 0, replay_bitmap = 0`, and clears `epoch_resync_allowed = FALSE`.

     * Otherwise, if `boot_epoch < devices.boot_epoch`, rejects with `409 BOOT_EPOCH_REGRESSION` and triggers `REAUTH_REQUIRED`.

   * **Epoch-Agnostic Active Session Collision Check:** If the device's current certificate under the active Intermediate CA is not revoked and `devices.last_ingested_at >= NOW() - INTERVAL '30 seconds'`, triggers `REAUTH_REQUIRED` and raises a `SECURITY_ANOMALY_ALERT` regardless of `boot_epoch`.

4. **Activation:** Revokes prior certificates for `device_id` (`SUPERSEDED_BY_REENROLL`), closes open Netty sockets, updates `devices.boot_epoch`, and returns `{new_cert_pem, assigned_boot_epoch, current_assignment_id, assignment_active_from}`.

### Non-Destructive Anomaly Response and Clinician Recovery

* **Action via Signer Revocation RPC:** Any anomaly trigger invokes `/internal/v1/signer/revoke`, marking the certificate `REVOKED`, setting `devices.trust_state = 'REAUTH_REQUIRED'`, closing Netty channels, and inserting a `SECURITY_ANOMALY_ALERT`. Historical telemetry remains `ACCEPTED`.

* **Recovery Path from `REAUTH_REQUIRED`:** A clinician inspects the alert on Port `8445` and submits either:

  1. **Clear Device (`POST /api/v1/admin/devices/{id}/restore-active`):** WebAuthn-authenticated action setting `trust_state = 'ACTIVE'` and `epoch_resync_allowed = TRUE` so a benignly reset or state-reset device can recover via `/re-enroll` with server-assigned `stored_epoch + 1`.

  2. **Confirm Compromise (`POST /api/v1/admin/devices/{id}/quarantine`):** WebAuthn-authenticated action transitioning `trust_state = 'QUARANTINED'`, clearing the DEK, and sanitizing lookback telemetry.

### Revocation Enforcement Path

| Layer | Mechanism | Timing |
| :--- | :--- | :--- |
| **Handshake** | `DynamicMtlsTrustManager` rejects any certificate not in an accepted status. | Every new TCP connection |
| **Per-request** | `CertStatusResolver` checks status and validity window before the controller runs. Cache entries expire after 5 seconds and are evicted on every revocation event. | Every telemetry request |
| **Live socket eviction** | The Signer revoke RPC calls `ActiveSessionRegistry.evictByCert()`, which closes the Netty `Channel`. Multi-gateway deployments broadcast the event over Redis pub/sub. | Milliseconds after revocation |
| **Backstop poller** | Each gateway polls `certificates` every 3 seconds for `revoked_at >= last_poll_start - 30s` and evicts idempotently. | At most 3 seconds if an event is missed |
| **Interoperable record** | The Intermediate CA publishes a signed X.509 v2 CRL (`nextUpdate` = 24h) for external relying parties. The CRL is the published record, not the enforcement path. | Republished on each revocation |

### Degraded-Mode Behavior

| Failure | Behavior |
| :--- | :--- |
| **KMS or Signer unavailable** | Existing certificates keep working until `notAfter`. Renewal starts at 8 hours, leaving a 4-hour buffer; new enrollments pause. |
| **PostgreSQL unavailable** | Gateways return `503` with a jittered `Retry-After` and never acknowledge uncommitted batches; wearables keep frames in flash and drain them in FIFO order after recovery. |
| **Revocation event lost** | The backstop poller evicts within 3 seconds. |
| **Intermediate CA compromised** | The standby Intermediate (#3) is promoted, all #2 leaf certificates are bulk-revoked as `CA_COMPROMISE`, and devices re-enroll through Protocol C with jittered `Retry-After`. |

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

### Single-CTE Conflict-Safe Sliding Window and Insert

Sequence uniqueness is keyed on `(device_id, boot_epoch, sequence_number)` with `ON CONFLICT DO NOTHING` so concurrent duplicate retries never trigger transaction-aborting `SQLSTATE 23505` errors:

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

* **Atomic Acceptance:** If `batch_id` is returned, both the sliding-window bit update and the telemetry row insert committed atomically.

* **Duplicate / Retry Behavior:** Concurrent duplicates are serialized by the row lock that `window_update` takes on the `devices` row; the second statement re-evaluates its `WHERE` clause after the first commits, finds the sequence bit set, and matches `0` rows. `ON CONFLICT DO NOTHING` only takes effect when a wearable reuses a `batch_id` under a new sequence number: the window update still commits, consuming that sequence number (it is never reused), and the batch is rejected. In every no-row case, the service queries `telemetry_records` for `(:deviceId, :batchId)`: if found with an identical `payload_sha256` and `boot_epoch`, it returns `200 OK (idempotent_retry: true)`; otherwise it returns `409 Conflict` (`DUPLICATE_SEQUENCE_REPLAY`, `BOOT_EPOCH_MISMATCH`, or `SEQUENCE_TOO_OLD`).

## 6. Activity-Context Clinical Drift Engine and Lineage-Tracked Alert Retraction

*Z-score thresholds, the calibration window size, and acute physiological limits are configurable engineering defaults and have not been clinically validated.*

### Linear Evaluation Pipeline

1. **Hardware / ADC Plausibility Bounds:** `heart_rate_bpm` outside `[15, 300]` or `spo2_pct` outside `[40, 100]` is stored as `REJECTED_IMPLAUSIBLE`.

2. **Activity and Motion Context Classification:** Classifies each batch as `RESTING` (`step_cadence_spm == 0` and `motion_g_rms < 0.05g` sustained for at least 5 minutes) or `EXERTION`.

3. **Signal Perfusion and Acute Threshold Evaluation:**

   * If `perfusion_index < 0.5`, stores as `SIGNAL_DEGRADED`; if 3 consecutive degraded batches also exhibit `spo2_pct <= 90.0` or `heart_rate_bpm <= 40` / `>= 150`, emits `LOW_PERFUSION_CRITICAL_ALERT`.

   * If `perfusion_index >= 0.5`, stores as `ACCEPTED` and evaluates context-aware acute bounds (`RESTING` HR `>= 140` or `<= 40`; `EXERTION` HR `> 0.95 * (208 - 0.7 * age)`; any-state `spo2_pct <= 90.0`), emitting `ACUTE_PHYSIOLOGICAL_ALERT` (`baseline_version = NULL`).

4. **Resting Baseline Calibration and Drift Z-Scores:** Evaluated strictly on `ACCEPTED` batches classified as `RESTING`. Accumulates 30 resting batches to lock `ref_*` mean/SD (`baseline_state = 'LOCKED'`), then flags `POTENTIAL_PHYSIOLOGICAL_DRIFT` (recording the active `baseline_version`) when at least 2 of 3 metrics breach directional thresholds (Z_HR >= +2.0, Z_HRV <= -1.8, Z_SpO2 <= -1.5) across 4 consecutive resting batches.

### Dual-Timestamp Quarantine and Scoped Alert Retraction

When an operator executes a WebAuthn-authenticated quarantine (`POST /api/v1/admin/devices/{id}/quarantine` with `lookback_minutes`), a single transaction sanitizes lookback records (`ingested_at` OR `measured_at` within the window), resets any calibration-poisoned baseline back to `'CALIBRATING'` with an incremented `baseline_version`, and retracts only alerts directly triggered by quarantined batches or drift alerts computed against the tainted `baseline_version` (leaving unrelated acute or security alerts intact):

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
        ref_spo2_sd           = NULL
    WHERE a.device_id = :deviceId
      AND a.calibration_batch_ids && ARRAY(SELECT batch_id FROM quarantined_batches)
    RETURNING a.assignment_id, (a.baseline_version - 1) AS old_baseline_version
)
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
  );
```

## 7. PostgreSQL Schema and Tamper-Evident Audit Chain

### Tamper-Evident Audit Log (`security_audit_log`)

Each entry hashes the previous entry's hash plus its own fields under a PostgreSQL transaction-scoped advisory lock (`pg_advisory_xact_lock`), preventing concurrent writes from forking the chain. Every 60 seconds, the chain head is signed with KMS Key #4 and written to AWS S3 Object Lock (`COMPLIANCE` mode) so even a database superuser cannot rewrite history undetected.

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
```

## 8. Hackathon Live Demo Scope vs. Production Architecture

For the 24-hour solo build, the Reactor Netty Gateway, Admin Plane, and CA Signer run as modular packages inside a single Spring Boot process alongside PostgreSQL and **LocalStack KMS** in Docker Compose (`http://localhost:4566`, configured via `LOCALSTACK_AUTH_TOKEN` in a gitignored `.env` file and placeholder SDK credentials `test` / `test`). LocalStack emulates the AWS KMS API (`ECC_NIST_P256`, `kms:Sign`) for stage execution with no AWS dependency during the demo, without providing the hardware HSM key-custody or IAM isolation guarantees of production AWS KMS, while the architecture specification defines the VPC subnet split, per-service PostgreSQL roles, multi-region KMS replicas, and drop-in Keytos EZCA issuer support for production deployment.

| Subsystem | Runs Live on Stage (Hackathon Build) | Designed in Specification (Production Deployment) |
| :--- | :--- | :--- |
| **PKI and AWS KMS Signing** | **Live:** LocalStack KMS (`ECC_NIST_P256`, `kms:Sign` via `software.amazon.awssdk:kms`) emulating the KMS API surface locally with local-profile-only startup key reconciliation, RFC 5280 X.509v3 leaf synthesis via BouncyCastle, and downloadable signed X.509 v2 CRL (`/api/v1/pki/intermediate-crl.pem`). | Production AWS KMS hardware-backed key custody, Multi-Region KMS replicas (`mrk-*` across `us-east-1` and `us-west-2`), Multi-AZ RDS failover, Standby Intermediate KMS Key (#3) ceremony, and drop-in Keytos EZCA issuer replacement. |
| **Listeners and mTLS Eviction** | **Live:** Reactor Netty Port `8443` (`ClientAuth.REQUIRE`, resumption disabled) + Port `8444`/`8445` control endpoints, and `ActiveSessionRegistry` calling `channel.close()` on live mTLS sockets. | Separate JVM deployment for the internal CA Signer Service and separate PostgreSQL role grants (`vitalsshield_gateway_role` vs. `vitalsshield_signer_role`). |
| **Admin Passkey and Enrollment** | **Live:** Browser **WebAuthn Passkey** (MacBook Touch ID on `localhost`) gating device provisioning and quarantine, plus stateless HMAC `/challenge` and `/enroll`. | Chaining the raw WebAuthn binary assertion into KMS Key #4 `dek_registry_kms_sig` and `passkey_registry_kms_sig`. |
| **Telemetry and Replay Window** | **Live:** End-to-end **RFC 7515 JWS (`ES256`)** signature verification against the TLS client certificate's public key + single-CTE atomic 64-bit sliding replay bitmap in PostgreSQL. | Hardware flash ring-buffer persistence on physical wearable silicon. |
| **Quarantine and Alert Retraction** | **Live:** Resting Z-score drift evaluation, dual-timestamp (`ingested_at OR measured_at`) retroactive quarantine, baseline recalibration reset, and automatic `RETRACTED_BY_QUARANTINE` alert retraction. | Background S3 Object Lock (`COMPLIANCE` mode) WORM checkpointing of the `pg_advisory_xact_lock` hash-chained audit log. |

## Appendix A: Final Specification Verification Log

| Area | Verification Update Applied |
| :--- | :--- |
| **State Partition vs. Factory Wipe** | Clarified that a state-partition reset preserves the separate DEK key partition for `/restore-active` + `/re-enroll` recovery, whereas a full factory wipe erasing the DEK requires fresh Protocol A re-provisioning. |
| **Re-Provisioning Epoch Advance** | Protocol A now revokes prior certificates and assigns `stored_boot_epoch + 1` with a reset replay window when re-provisioning a factory-wiped device, preventing sequence collisions and active-certificate index violations. |
| **First-Use & Drain Handshake Allowance** | Updated `DynamicMtlsTrustManager` and `CertStatusResolver` to permit `ACTIVE`, `ISSUED_PENDING_USE`, and `RENEWED` (while `NOW() < grace_expires_at`) so renewed certificates and draining connections operate cleanly. |
| **Server-Assigned `boot_epoch`** | Enforced server-assigned `boot_epoch` progression: wearables never increment epochs independently, rejecting client-incremented values with `409 BOOT_EPOCH_INVALID` (`REAUTH_REQUIRED`). |
| **CTE Conflict Semantics** | Clarified that concurrent duplicate packets serialize on the `devices` row lock so the second re-evaluates `WHERE` and matches `0` rows, while `ON CONFLICT DO NOTHING` handles `batch_id` reuse under a new sequence number by consuming that sequence number and rejecting the batch. |
| **Drift-Scoped Alert Lineage** | Added `chk_alert_baseline_lineage` on `clinical_alerts` restricting `baseline_version` to `POTENTIAL_PHYSIOLOGICAL_DRIFT` alerts so acute and security alerts survive baseline resets. |
| **Illustrative Digest Labeling** | Explicitly marked the sample `x5t#S256` and `firmware_hash` values in Section 5 as format-only placeholders. |
| **Local KMS Emulation** | The demo targets LocalStack KMS through an endpoint override. KMS API calls, key specs (`ECC_NIST_P256`), signing algorithm (`ECDSA_SHA_256`), X.509 profiles, and schema are identical across profiles; HSM-backed key custody and IAM enforcement apply only to the production AWS KMS profile. CA key regeneration on startup is restricted to the local profile. |