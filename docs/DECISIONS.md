# Decisions

Resolved deviations and clarifications of `docs/vitalsshield_technical_architecture_specification.md`. Notes and
reports cite these by number ("DECISIONS #23").

| # | Spec section | Resolution |
| :--- | :--- | :--- |
| 1 | §4, §6 | Quarantine allowed from ACTIVE or REAUTH_REQUIRED; revokes all non-revoked certs (KEY_COMPROMISE), evicts, then sanitizes. |
| 2 | §3 | Server TLS Issuing CA under Root (EKU serverAuth) issues the gateway cert; simulator trusts Root; Device Intermediate stays clientAuth-only. |
| 3 | §4, §8 | Live Protocol A includes the Key #4 DEK anchor; passkey_registry_kms_sig and Signer-side WebAuthn re-verification are "Designed". |
| 4 | §4, §7 | Admin API: setup code at first boot; POST /admin/passkeys, /admin/devices (begin/finish), /admin/assignments, /admin/assignments/{id}/close, /admin/devices/{id}/restore-active, /admin/devices/{id}/quarantine. |
| 5 | §8 | Protocol B should-have; Protocol C and split-brain stretch; /challenge live only if B or C is built. |
| 6 | §6, §8 | Demo clock compression (12 h back-offset, +60 s per batch, about 1 batch/s, capped at server time); demo calibration window 10 batches; disclosed in §8. |
| 7 | §2, §3 | dek_spki_der renamed to dek_spki_der_b64. |
| 8 | §4, §8 | Redis pub/sub broadcast is "Designed" (single process). |
| 9 | §7 | If WebAuthn is cut, a V2 migration makes the webauthn_* token columns nullable. |
| 10 | §3, §4 | Provisioning is begin/finish; ProvisioningDigest is the WebAuthn challenge. |
| 11 | §4, §5 | Revocation latency = revoke start to channel close complete; e2e asserts max < 500 ms over 5 runs. |
| 12 | §3 | Local reconciliation is all-or-nothing over four keys; old ca_issuers REVOKED, never deleted; leaves revoked (HIERARCHY_REBUILD); devices reset; trust file rewritten after commit. |
| 13 | §4, §8 | If the eviction backstop poller is not built, §4 and §8 mark it "Designed". |
| 14 | §3, §7 | kms_keys table holds all four KMS keys by purpose; reconciliation reads ACTIVE rows only. |
| 15 | §3 | Gateway TLS private key is ephemeral, in memory, regenerated each boot; 24 h cert from the Server TLS CA; the one key outside KMS. |
| 16 | §3 | Boot order: Flyway, reconcile, gateway TLS, trust anchors, deny-list seed, CRLs published, bind listeners. |
| 17 | §3 | KMS signing uses MessageType DIGEST; RAW caps messages at 4096 bytes, which a CRL passes at about 100 entries. |
| 18 | §3 | SKI = SHA-256 of SPKI DER (RFC 7093 §2 method 4). |
| 19 | §3, §7 | App revocation reasons map to RFC 5280 CRLReason; unspecified omits the extension. |
| 20 | §3 | Rebuild keeps QUARANTINED/DECOMMISSIONED trust states; DEK cleared for all. |
| 21 | §4 | Protocol C nonce fixed at 16 bytes. |
| 22 | §7 | ca_issuers lacks revocation metadata; root CRL derived; production gap. |
| 23 | §4 | CertStatusResolver has no 5 s cache; DB lookup per request on boundedElastic. |
| 24 | §4 | Handshake uses an in-memory deny-list (with deniedFrom), not an accepted-status lookup; post-handshake gate checks every completed handshake, including resumed ones. |
| 25 | §1, §8 | All listeners bind 127.0.0.1 by default; admin always loopback. |
| 26 | §2 | TLS resumption prevented by invalidating each server session after the handshake check (the JDK ticket property alone left cache-based resumption on). Observed (Phase 2.1, JDK 21.0.13, OpenSSL 3.6.4 s_client): the server still sends one NewSessionTicket per connection, but a client presenting it gets a full handshake ("New", never "Reused"); after revoke that full handshake is refused by the trust manager (alert 46, certificate unknown). |
| 27 | §4 | CRLs cached and republished on revocation and before nextUpdate; HTTP GET never signs. |
| 28 | §4 | The 30 s deny-list refresh is a backstop for the handshake deny-list. It is not the spec's 3 s eviction poller (still a Phase 9 stretch) or Redis (Designed). |
| 29 | §4 | The CRL endpoint has no rate limit. Production publishes CRLs to object storage behind a CDN and rate-limits 8444 at the L4 load balancer. "Designed". |
| 30 | §4 | Each gateway process caches its own CRL. With multiple gateways the CRL Number can briefly differ between them (it still always increases). Production publishes one CRL to shared storage. "Designed". |
| 31 | §4 | Protocol A defines a "first-time device" as one with no prior certificates row. Such a device keeps boot_epoch = 1; any other device gets boot_epoch + 1. provisioned_at cannot be used because hierarchy rebuilds reset it. |
| 32 | §4, §8 | Until Phase 6, a dev seed tool creates the device, the ACTIVE assignment, and the bootstrap token. Its WebAuthn fields are visibly fake (DEV-SEED-NOT-WEBAUTHN). It runs as a Gradle task from the test classpath, refuses any database other than the local Compose database, and is never an HTTP endpoint. |
| 33 | §3, §4 | Signatures outside JWS (DEK proofs, KMS anchors) are DER ECDSA. Only JWS uses raw R\|\|S. |
| 34 | §4 | Enrollment token semantics: a cryptographic or proof failure revokes the token (fail closed); a transient KMS or DB failure returns it to ISSUED; a token stuck in CLAIMING for more than 2 minutes can be claimed again. |
| 35 | §4, §5 | certificates.cert_thumbprint_s256 stores base64url(SHA-256(cert DER)), 43 characters, which is exactly the JWS x5t#S256 value. |
| 36 | §4 | The simulator uses 127.0.0.1 URLs (the gateway cert has an IP SAN) with hostname verification on. |
| 37 | §2 | Deny-listed certs fail with a CertPathValidatorException(REVOKED) cause, and validity failures keep their EXPIRED cause, so JSSE can send alerts 44 and 45. Observed (Phase 3, JDK 21.0.13): the server still sends alert 46 (certificate_unknown) for every rejected client certificate. JDK 21 `sun.security.ssl.CertificateMessage.checkClientCerts` (TLS 1.2 and 1.3 paths) always calls `fatal(Alert.CERTIFICATE_UNKNOWN, ce)`; the cause-to-alert mapping (`getCertificateAlert`) is used only when a client checks a server. The cause chain is kept (harmless; a future JDK or another provider may use it). |
| 38 | §3, §4 | Serial reservation ledger: every device leaf serial is reserved in issued_serials (RESERVED) inside the same short transaction that claims the token, before any KMS call. Activation marks it RECORDED. An aborted activation marks it VOIDED and, if the signed leaf is in hand, stores it in certificates as REVOKED (REPLACED_BEFORE_USE) and deny-lists it. A sweep at boot and on every stale reclaim voids RESERVED serials older than 2 minutes. CRLs list REVOKED certificates plus VOIDED serials (reason superseded), so every device serial the CA ever signed is either recorded or revocable, even when the certificate itself was lost. |
| 39 | §3 | Gateway leaves (Server TLS CA) are not tracked in issued_serials, and the Server TLS CA publishes no CRL. Each gateway leaf lives 24 h and its key never leaves JVM memory. A Server TLS CA CRL is "Designed". |
| 40 | §5 | Sequence numbers start at 1; a sequence_number below 1 is rejected. |
| 41 | §4, §8 | Until Phase 6, /api/v1/admin/** (except boot-status) requires the boot-generated setup code as a bearer token. The code is written to var/admin/setup-code (permissions 600) and never printed or logged; only its path is logged. This is also the fallback if WebAuthn is cut. |
| 42 | §6 | Quarantine locks the devices row FOR UPDATE and sets QUARANTINED before running the sanitize CTE as a separate statement in the same READ COMMITTED transaction, so an in-flight ingest cannot commit an ACCEPTED row after the quarantine. |
| 43 | §5 | JWS header policy: alg must be ES256; typ must be vitalsshield.telemetry+jws; x5t#S256 is required; jwk, jku, x5c, x5u, and crit are rejected. The verification key comes only from the TLS client certificate. Unknown payload fields are rejected. |
| 44 | §5, §8 | Simulator offline handling is simplified: it retries the same frame (same batch_id and sequence number) until it succeeds. The flash ring buffer stays "Designed". |
| 45 | §4 | Quarantine also revokes the device's outstanding ISSUED and CLAIMING bootstrap tokens. |
| 46 | §6 | Phase 4 classifies telemetry by plausibility bounds and perfusion only (REJECTED_IMPLAUSIBLE, SIGNAL_DEGRADED, ACCEPTED). Activity context, acute thresholds, calibration, drift, and alerts arrive in Phase 7. |
| 47 | §8 | Dashboard: Next.js static export served on the admin port from a filesystem directory (vitalsshield.dashboard.dir, default dashboard/out). The operator pastes the admin setup code at sign-in; it is held in sessionStorage until Phase 6 adds WebAuthn. |
| 48 | §8 | The dashboard polls every 500 ms instead of using SSE: EventSource cannot send an Authorization header. |
| 49 | §3 | KMS health monitor: DescribeKey on the four ACTIVE keys every 30 s. It reports and alarms but never rebuilds at runtime; recovery means restarting the server, which rebuilds and revokes every device. |
| 50 | §8 | Serials are displayed as uppercase whole-byte hex, the way `openssl x509 -serial` and `openssl crl -text` print them. The stored format is unchanged. |
| 51 | §8 | Devices and tokens created by the dev seed tool show a visible DEV SEED badge on the dashboard. |
| 52 | §8 | The Next.js 16 static export contains inline scripts (3 in index.html, including the `_R_` hydration bootstrap), so `script-src 'self'` alone breaks it. Instead of `'unsafe-inline'`, the dashboard handler adds the SHA-256 hash of every inline script in the served HTML file to `script-src` (computed at serve time, cached per file and modification time). External scripts are still `'self'` only. |
| 53 | §8 | npm audit reports moderate advisories only in dashboard lint tooling (minimatch under typescript-eslint); production dependencies have 0. Accepted for the hackathon; no audit fix mid-build. Re-check before any deployment. |
