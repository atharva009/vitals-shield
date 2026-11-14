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
