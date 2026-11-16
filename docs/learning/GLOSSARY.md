# Glossary

Alphabetical. The tag after each term is the phase that introduced it in this codebase.

**Advisory lock** (Phase 1): A PostgreSQL lock on an arbitrary number that the application chooses, not on a row or
table. `pg_advisory_xact_lock(n)` holds it until the transaction ends. `HierarchyReconciler` takes one so two
processes cannot commit a rebuild at the same time.

**AKI (Authority Key Identifier)** (Phase 1): A certificate extension that holds the key identifier of the CA that
signed the certificate. It is how a verifier finds the right issuer certificate. Ours holds only the `keyIdentifier`
field (the issuer's SKI), with no issuer name or serial.

**Allow-list** (Phase 2): A set of things that are permitted; anything not listed is refused. For certificates, an in-memory allow-list must be refreshed to learn about new certificates, so a device that enrolls and connects before the next refresh is wrongly refused. VitalsShield does not use one in the handshake path for that reason.

**ARN (Amazon Resource Name)** (Phase 0): AWS's full identifier for a resource, for example
`arn:aws:kms:us-east-1:000000000000:key/857ab58e-...`. It includes the service, region, account, and key ID. We store
the full ARN in `kms_keys.kms_key_id` and `ca_issuers.kms_primary_arn`, not the bare key ID, so a key reference is
unambiguous across regions and accounts.

**ASN.1** (Phase 1): Abstract Syntax Notation One, a language for describing data structures (sequences, integers,
bit strings, object identifiers). X.509 certificates and CRLs are defined in ASN.1. DER is one way of turning an
ASN.1 value into bytes.

**Atomic rename** (Phase 1): Writing a file under a temporary name and then renaming it over the target in one
filesystem operation. A reader sees either the whole old file or the whole new file, never a half-written one.
`TrustFileWriter` writes the Root PEM this way with `ATOMIC_MOVE` and `REPLACE_EXISTING`.

**Attestation** (Phase 6): An authenticator's signed statement of its own model, checked against a vendor root. We request "none" (DECISIONS #63): trust in a new passkey comes from who registered it.

**authenticatorData** (Phase 6): Bytes built and signed by the authenticator: SHA-256 of the RP id, flags (UP, UV, AT, ...), a 4-byte signature counter, and at registration the credential id and COSE public key.

**base64url** (Phase 4): Base64 with `-` and `_` instead of `+` and `/`, and no `=` padding, so the text is safe in URLs and headers. JWS parts and x5t#S256 use it.

**Basic Constraints** (Phase 1): A certificate extension that says whether the subject is a CA (`CA:TRUE`) and so may
sign other certificates. A verifier must reject any chain where a non-CA certificate signed another certificate. We
mark it critical on every certificate.

**Big-endian** (Phase 0): Writing a multi-byte number with the most significant byte first. The 32-bit number 3 is
`00 00 00 03` in big-endian. All our canonical encodings use big-endian (`uint32_be`, `int64_be`), the same as network
byte order.

**boot_epoch** (Phase 3): A server-assigned counter that partitions a device's telemetry sequence numbers. A re-provisioned device gets the next epoch so its restarted sequence numbers cannot collide with old ones. A device never chooses its own (DECISIONS #31).

**Bootstrap token** (Phase 3): A one-time secret that authorizes one enrollment of one device. Ours is 32 random bytes (base64url), valid one hour by default, stored only as its SHA-256 hash, and CONSUMED after use. Until Phase 6 the dev seed tool creates it instead of a clinician's WebAuthn action.

**boundedElastic** (Phase 1): A Reactor scheduler with a capped pool of threads meant for blocking work such as
JDBC or a synchronous HTTP call. Moving a blocking call onto it keeps event loop threads free.
`KmsSigner.signDigest` uses `subscribeOn(Schedulers.boundedElastic())`.

**CA (Certificate Authority)** (Phase 1): An entity whose signature on a certificate vouches that the public key in
it belongs to the named subject. A CA has its own key pair and its own certificate with `CA:TRUE`. Our CAs are the
Root, the Device Issuing Intermediate, and the Server TLS CA.

**Canonical encoding** (Phase 0): A single, exact way to turn structured data into bytes, so two parties produce the
same bytes for the same values. Signatures are over bytes, so the layout must be fixed. `CanonicalEncodings` defines
our six layouts from spec Section 3 and Protocol C.

**Certificate** (Phase 1): A signed statement binding a public key to a name, plus rules about how the key may be
used and for how long. Anyone with the issuer's public key can check the signature. We use X.509 v3 certificates.

**Certificate chain** (Phase 1): An ordered list from a leaf certificate up to a trusted root, where each
certificate is signed by the next one. Our device chain is device leaf, Device Issuing Intermediate, Root. A verifier
checks each link.

**certificate_required alert** (Phase 2.1): TLS 1.3 alert number 116, sent by a server that asked for a client certificate and got none. Because the client has already finished its side of the handshake, it only sees this alert on its next read; `openssl s_client </dev/null` exits before that and looks successful.

**CertificateRequest** (Phase 2): The TLS handshake message in which the server asks the client for a certificate. It can list the CA names the server accepts; ours lists only the current Device Intermediate (`getAcceptedIssuers`). It is sent only on the mTLS port.

**Channel** (Phase 2): Netty's object for one open network connection. Closing it sends a TLS close and ends the TCP connection, even if the client is idle on keep-alive. `ActiveSessionRegistry` keeps the channels per certificate so a revoke can close them.

**Clickjacking** (Phase 5): Loading a page inside an invisible frame on another site so a user clicks its buttons without knowing. `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` stop the dashboard (and its quarantine button) from being framed at all.

**clientDataJSON** (Phase 6): JSON the browser builds for every WebAuthn call: type, challenge, and the page's origin. Its SHA-256 is part of what the authenticator signs, which is what makes passkeys phishing resistant.

**Common table expression (CTE)** (Phase 4): A named sub-query introduced with `WITH`. In Postgres a CTE can itself be an UPDATE or INSERT; all parts run as one statement, so the spec's window update and telemetry insert commit or fail together.

**Content Security Policy (CSP)** (Phase 5): A response header that tells the browser which sources a page may load scripts, styles, images, and connections from. The admin port sends `script-src 'self'` plus hashes, so injected inline script does not run.

**ContentSigner** (Phase 1): A BouncyCastle interface: the certificate builder writes the bytes to be signed into its
output stream, then asks for the signature. It also reports which signature algorithm it uses. `KmsContentSigner`
implements it by hashing locally and asking KMS to sign the digest.

**CORS (Cross-Origin Resource Sharing)** (Phase 5): Headers by which a server allows pages from other origins to read its responses. The admin API sends none, so only pages from `http://127.0.0.1:8445` itself can read it.

**COSE key** (Phase 6): A public key encoded as a CBOR map with integer labels (RFC 9052). For ES256: kty 2, alg -7, crv 1, x and y. Stored in `clinician_passkeys.public_key_cose_der_b64`.

**Critical extension** (Phase 1): An extension marked so that a verifier that does not understand it must reject
the certificate. Marking Basic Constraints and Key Usage critical means an old or partial verifier cannot silently
ignore them. Non-critical extensions may be skipped by verifiers that do not know them.

**CRL (Certificate Revocation List)** (Phase 1): A list, signed by a CA, of serial numbers of certificates it issued
that are revoked before their expiry. A relying party downloads it and refuses any listed certificate. Ours are X.509
v2 CRLs produced by `CrlService`.

**CRL Distribution Point** (Phase 1): A certificate extension that tells a verifier where to download the CRL that
covers this certificate. Our device leaf points to `https://localhost:8444/api/v1/pki/intermediate-crl.pem`. The URL
is not served yet; HTTP endpoints come in a later phase.

**CRL Number** (Phase 1): A CRL extension holding a number that increases with each CRL the issuer publishes. It
lets a relying party tell which of two CRLs is newer. We keep it in `ca_issuers.crl_number` and increment it in the
same transaction that reads the revoked entries.

**CRL republication** (Phase 2.1): Signing a new CRL when its contents change or before it goes stale, and serving the cached copy in between. Since Phase 2.1 our CRLs are republished after a revocation commits and before nextUpdate, and an HTTP GET never signs (DECISIONS #27).

**CSP hash source** (Phase 5): A `'sha256-<base64>'` entry in `script-src`. The browser runs an inline script only if the SHA-256 of its exact text is listed. `DashboardRoutes` computes these for the Next.js export's inline scripts instead of allowing `'unsafe-inline'` (DECISIONS #52).

**CSR (Certificate Signing Request)** (Phase 3): A PKCS#10 document holding a public key, a requested name and extensions, and a signature by the matching private key. Our CA uses only the public key and checks the signature (proof of possession); everything else is ignored.

**CSRF (cross-site request forgery)** (Phase 6): Another site making the browser send a request that carries our cookie. Stopped by `SameSite=Strict` and an Origin check on every non-GET admin request (DECISIONS #59).

**Deadlock** (Phase 6.1): Two transactions each holding a lock the other is waiting for. Postgres detects the cycle and aborts one with SQLSTATE 40P01. Prevented here by taking the audit advisory lock last (DECISIONS #67).

**DEK (Device Enrollment Key)** (Phase 3): The wearable's long-lived P-256 key, kept in the simulator's key partition (`keys/dek.key`). It proves identity at enrollment and survives state resets. Its public key is anchored in `devices` by a KMS Key #4 signature.

**Deny-list** (Phase 2): A set of things that are refused; anything not listed passes this check. `CertificateDenyList` holds revoked, expired, and superseded certificates in memory, keyed by issuer key hash and serial. A new certificate is not on it, so it connects immediately; the per-request DB check confirms its real status.

**DER (Distinguished Encoding Rules)** (Phase 1): A strict binary encoding for ASN.1 where every value has exactly
one valid encoding. Certificates are signed over their DER bytes, so the encoding must be unique. `.der` files and the
bytes inside PEM are DER.

**DER-encoded ECDSA signature** (Phase 0): An ECDSA signature written as an ASN.1 `SEQUENCE { INTEGER r, INTEGER s }`
in DER, usually 70 to 72 bytes for P-256. X.509 certificates and CRLs use this form, and AWS KMS returns it.
`KmsSmokeIT.signatureIsDer` checks that KMS output parses this way.

**DescribeKey** (Phase 1): The KMS API call that returns a key's metadata, including its state (`Enabled`,
`Disabled`, `PendingDeletion`, ...). `KmsKeyAdmin.describeEnabled` returns true only if the call succeeds and the state
is `Enabled`.

**Dev seed tool** (Phase 3): `./gradlew :server:seedDemoDevice`: creates a device, an ACTIVE assignment, and a bootstrap token in the local Compose database, with visibly fake WebAuthn fields. It refuses any other database and is never an HTTP endpoint (DECISIONS #32).

**DEV_SEED passkey** (Phase 6.1): The seed tool's software passkey (`clinician_passkeys.purpose = 'DEV_SEED'`). It may only finish the seed tool's provisioning in the local profile; sign-in and step-up are refused (DECISIONS #66).

**Digest** (Phase 1): The fixed-size output of a hash function. A SHA-256 digest is always 32 bytes, whatever the
input size. We send KMS the 32-byte digest of the data to be signed instead of the data itself.

**Discoverable credential** (Phase 6): A passkey stored with its user handle on the authenticator, so sign-in can start without a username (empty allowCredentials). Required here.

**DN (Distinguished Name)** (Phase 1): The structured name of a certificate's subject or issuer, made of attributes
such as `CN` (common name) and `O` (organization). Our Root DN is "CN=VitalsShield Root CA, O=VitalsShield". In DER it
is a sequence of RDNs.

**Dual-timestamp quarantine** (Phase 4): Selecting batches for quarantine when either the device's `measured_at` or the server's `ingested_at` is inside the lookback window, so backdated forgeries and late uploads are both caught (spec Section 6).

**ECDSA** (Phase 0): Elliptic Curve Digital Signature Algorithm. The signer uses a private key and a random value to
produce a pair of numbers (r, s); anyone with the public key can verify them. Every signature in VitalsShield is ECDSA
on P-256 with SHA-256.

**Ephemeral port** (Phase 2): A free port number picked at run time instead of a fixed one. Integration tests use them for all three listeners so they never collide with a running server on 8443 to 8445. `TestPorts` finds free ones by briefly opening port 0.

**ES256** (Phase 4): ECDSA on P-256 with SHA-256, as named in JWS (RFC 7518). Its signature is the 64-byte R||S form, not DER.

**Event loop** (Phase 1): A small number of threads that each handle many connections by never blocking: they run
short callbacks and move on. Reactor Netty uses event loops. A blocking call on an event loop stalls every connection
on that thread, which is why KMS calls must not run there.

**EventSource** (Phase 5): The browser API for Server-Sent Events, a one-way stream of updates from server to page. It cannot set an `Authorization` header, which is why the dashboard polls with `fetch` instead (DECISIONS #48).

**Eviction** (Phase 2): Closing a client's live connection on purpose. After a revoke, `SignerRevocationService` closes every channel for that certificate; the measured time was a few milliseconds. The client must reconnect and is then refused.

**Extended Key Usage (EKU)** (Phase 1): A certificate extension listing application purposes for the key, by OID,
such as TLS client authentication (`1.3.6.1.5.5.7.3.2`) or TLS server authentication (`1.3.6.1.5.5.7.3.1`). It narrows
what the key may be used for at the protocol level. Our device leaf has clientAuth only, marked critical.

**Extension** (Phase 1): An extra field in an X.509 v3 certificate, identified by an OID, with a critical flag and a
DER value. Extensions carry most of the policy: Basic Constraints, Key Usage, EKU, SKI, AKI, SAN, CRL Distribution
Points.

**Fail closed** (Phase 1): When a check cannot pass, stop instead of carrying on with a weaker guarantee. Outside
the `local` profile, `HierarchyReconciler` throws "KMS hierarchy incomplete; refusing to regenerate CA keys outside
the local profile" and the app does not start.

**Flyway** (Phase 0): A database migration tool. It runs numbered SQL files (`V1__baseline.sql`, ...) in order at
startup and records each in the `flyway_schema_history` table so it never runs one twice. In Spring Boot 4 it only
runs if `spring-boot-starter-flyway` is on the classpath.

**Golden vector** (Phase 1): A fixed input with a known correct output, computed by an independent implementation,
used to check another implementation. `scripts/golden_vectors.py` (Python stdlib only) produces the expected hex that
`CanonicalEncodingsTest` compares the Java output against.

**Hash-chained audit log** (Phase 6): `security_audit_log`, where each entry's hash covers the previous entry's hash, so editing any row breaks every later hash. Appends hold `pg_advisory_xact_lock` (DECISIONS #62).

**HSM (Hardware Security Module)** (Phase 1): A tamper-resistant device that generates and stores private keys and
performs signing inside itself, so the key never leaves. AWS KMS keys are backed by HSMs. LocalStack is not: its keys
are ordinary data in a container.

**HttpHandler** (Phase 2): Spring's lowest-level reactive HTTP entry point: one function from request to response. We build one from the application context (all controllers and WebFilters) and share it between the three Reactor Netty servers.

**Hydration** (Phase 5): React attaching event handlers and state to HTML that already exists. The Next.js export's inline scripts carry the data hydration reads, which is why they need CSP hashes.

**Idempotent retry** (Phase 4): Re-sending exactly the same frame (same batch_id and bytes) after a lost response. The server answers 200 with `idempotent_retry: true` and stores nothing new.

**Intermediate CA** (Phase 1): A CA whose certificate is signed by the Root (or another intermediate) and which signs
leaf certificates. It lets the Root key stay offline and lets you replace a compromised issuer without replacing the
Root. We have two: the Device Issuing Intermediate and the Server TLS CA.

**Issued serials ledger** (Phase 4): The `issued_serials` table (V2): every device leaf serial is RESERVED before signing, RECORDED on activation, or VOIDED; VOIDED serials go on the CRL and deny-list (DECISIONS #38).

**JWS (JSON Web Signature)** (Phase 4): RFC 7515. In compact form three base64url parts joined by dots: header, payload, signature over `header.payload`. VitalsShield telemetry batches are JWS signed by the device's OLK.

**Keep-alive** (Phase 2): HTTP/1.1 behaviour where one TCP connection carries many requests instead of one. It saves handshakes but means a client can stay connected for a long time, which is why revocation needs per-request checks and socket eviction, not only a handshake check.

**Key custody** (Phase 1): Who or what holds a private key and can use it. With KMS the custodian is the KMS service;
the application can ask for signatures but cannot read the key. In our local setup LocalStack is the custodian, which
gives no hardware protection.

**Key Usage (KU)** (Phase 1): A certificate extension with bit flags for what the key may do cryptographically:
`digitalSignature`, `keyCertSign` (sign certificates), `cRLSign` (sign CRLs), and others. Our CAs have
`keyCertSign, cRLSign`; our leaves have `digitalSignature`. We mark it critical.

**KMS (Key Management Service)** (Phase 0): AWS's managed service for creating keys and using them (sign, verify,
encrypt) through an API, without ever returning the private key. We use `ECC_NIST_P256` keys with `SIGN_VERIFY` usage.
Locally, LocalStack emulates the same API.

**KMS health monitor** (Phase 5): `admin/KmsHealthMonitor`. Reports HEALTHY, UNHEALTHY (a key disabled or missing), or UNKNOWN (the check failed). It alarms and never rebuilds; recovery is a deliberate restart (DECISIONS #49).

**Leaf certificate** (Phase 1): A certificate at the bottom of a chain, with `CA:FALSE`, issued to an end entity
such as a device or a server. It cannot sign other certificates. Our leaves are the device leaf and the gateway leaf.

**Length prefix** (Phase 0): A number written before a variable-length field that says how many bytes follow. It
stops an attacker from moving bytes between adjacent fields. Our strings are written as `uint32_be(len) || utf8`.

**LocalStack** (Phase 0): A container that emulates AWS APIs locally. We run it with `SERVICES=kms` and an auth token
from `.env`. It reproduces the KMS API, not HSM custody or IAM isolation, and loses its keys on restart unless
persistence is enabled.

**Lock ordering** (Phase 6.1): Acquiring locks in one fixed order in every transaction, so no cycle of waits can form. Our rule: row locks first, the `security_audit_log` advisory lock last.

**Loopback** (Phase 2): The network interface that only reaches the same machine, address 127.0.0.1. A socket bound to it cannot be reached from another host. All our listeners bind it by default, and the admin listener always does.

**Migration** (Phase 0): A versioned script that changes the database schema. Migrations run in order and are never
edited after they ship; a change goes in a new migration. Our only migration is `V1__baseline.sql`.

**mTLS (mutual TLS)** (Phase 2): TLS where the client also presents a certificate and proves it holds the private key, so the server knows which device is connected before reading any HTTP. Port 8443 requires it (`ClientAuth.REQUIRE`).

**NewSessionTicket** (Phase 2): A TLS 1.3 message the server sends after the handshake so the client can resume later. The JDK sent one per connection in our tests, 32 bytes with a 1-second lifetime, even with stateless tickets disabled.

**OID (Object Identifier)** (Phase 1): A globally unique dotted number that names something in ASN.1, such as
`1.2.840.10045.4.3.2` for ecdsa-with-SHA256 or `2.5.29.19` for Basic Constraints. Extensions, algorithms, and EKU
purposes are all identified by OIDs.

**OLK (Operational Leaf Key)** (Phase 3): The wearable's short-lived P-256 key, generated fresh at every enrollment and certified for 12 hours. It is used for mTLS and, from Phase 4, for signing telemetry. Kept in the state partition (`state/olk.key`).

**openssl verify** (Phase 1): The OpenSSL command that builds and checks a certificate chain:
`-CAfile` gives trusted roots, `-untrusted` gives intermediates, and the last argument is the leaf. It prints `OK`
and exits 0 on success. `PkiOpensslIT` uses it as an independent check of our certificates.

**Oracle (error oracle)** (Phase 3): A difference in responses that tells an attacker something, for example 'token expired' versus 'token unknown'. Enrollment returns one identical 401 body for every invalid-token case so it leaks nothing about which tokens exist.

**Origin** (Phase 5): Scheme, host, and port together, for example `http://127.0.0.1:8445`. Browsers isolate data by origin; 8444 and 8445 on the same host are different origins.

**P-256** (Phase 0): The NIST elliptic curve also called secp256r1 or prime256v1. It gives about 128-bit security
with 32-byte private keys. KMS calls it `ECC_NIST_P256`.

**Passkey** (Phase 6): A WebAuthn key pair for one site; on a Mac the private key is made by the Secure Enclave and synced in iCloud Keychain, and every use needs Touch ID. The server keeps only the public key.

**Passkey anchor** (Phase 6): `passkey_registry_kms_sig`, a KMS Key #4 signature over PasskeyAnchorBytes (credential id, clinician id, key hash). Verified before every assertion, so an SQL-inserted or swapped passkey fails (DECISIONS #56).

**Path traversal** (Phase 5): Using `..` (often percent-encoded as `..%2f`) in a URL to make a file server read outside its directory. `DashboardRoutes.resolve` decodes, normalizes, and checks the real path stays inside `dashboard/out`, answering 404 otherwise.

**pathLenConstraint** (Phase 1): A field in Basic Constraints that limits how many CA certificates may appear below
this one in a chain. Our Root has `pathlen:1` (one intermediate level) and each intermediate has `pathlen:0` (it may
sign only leaves).

**PEM** (Phase 1): DER bytes encoded in base64 between lines such as `-----BEGIN CERTIFICATE-----` and
`-----END CERTIFICATE-----`. It is the text form used in files and databases. `ca_issuers.cert_pem` holds PEM.

**PKCS#10** (Phase 3): The standard format for a certificate signing request (RFC 2986). See CSR.

**PKIX** (Phase 1): The IETF profile of X.509 for the internet, defined mainly in RFC 5280. It says which fields and
extensions certificates and CRLs should have and how to validate a chain. "RFC 5280 profile" in this project means
PKIX.

**Post-handshake gate** (Phase 2): Our check that runs when any TLS handshake completes on 8443, including resumed ones where the trust manager is not called. It reads the peer certificate from the session, registers the channel, and closes it if the certificate is deny-listed.

**Proof of possession** (Phase 3): Evidence that a party holds a private key, usually a signature made with it over data the verifier checks. The CSR signature proves possession of the OLK; the DEK proof signature proves possession of the DEK.

**PSK (pre-shared key)** (Phase 2): In TLS 1.3 resumption, a secret from an earlier session that the client and server both hold. The client proves it knows the PSK instead of sending a certificate, which is why resumption skips certificate checks.

**PSK resumption** (Phase 2.1): TLS 1.3's way of resuming: the client sends a pre-shared key identity from an earlier session's ticket instead of a certificate, and both sides derive keys from it. No certificate is sent and no trust manager runs. After Phase 2.1 our server refuses every PSK because the session behind it was invalidated.

**-purpose** (Phase 1): An `openssl verify` option that names the use you want to check a certificate for, such as
`sslclient` (TLS client) or `sslserver` (TLS server). OpenSSL then checks Key Usage and Extended Key Usage on the leaf
and on every CA in the chain. Our device leaf passes `sslclient` and fails `sslserver` with "unsuitable certificate
purpose".

**RDN (Relative Distinguished Name)** (Phase 1): One component of a DN, such as `CN=VitalsShield Root CA`. A DN is a
sequence of RDNs. The order of that sequence in DER is what OpenSSL prints.

**Reactor Netty** (Phase 2): The non-blocking network library under Spring WebFlux. It runs servers on a few event loop threads. We create three `HttpServer` instances with it in `ListenerManager`.

**READ COMMITTED** (Phase 4): Postgres's default isolation level: each statement sees data committed before that statement began, and an UPDATE that waited on a row lock re-checks its WHERE clause on the new row version. DECISIONS #42 relies on both.

**Reason code** (Phase 1): A CRL entry extension that says why a certificate was revoked, such as `keyCompromise`
(1), `superseded` (4), or `cessationOfOperation` (5). `CrlReasons` maps our database reasons to these codes. For
`unspecified` (0) we omit the extension, as RFC 5280 recommends.

**Reconciliation** (Phase 1): Comparing recorded state with actual state and fixing the difference. At startup
`HierarchyReconciler` compares `kms_keys` with what KMS reports, and either does nothing, rebuilds (local profile), or
refuses to start.

**Registry anchor** (Phase 3): A KMS Key #4 signature over (device_id, SHA-256 of the DEK public key, provisioning time), stored in `devices.dek_registry_kms_sig`. It lets the server detect a DEK changed by SQL alone. It does not prove the device or key is genuine.

**Relying party (RP) and RP ID** (Phase 6): The website that relies on WebAuthn, named by its RP ID, a domain ("localhost" here). An IP address cannot be an RP ID, so the admin plane runs at http://localhost:8445 (DECISIONS #55).

**Replay window** (Phase 4): The 64-bit `replay_bitmap` plus `last_sequence_num` on each device: a sequence is accepted once if it is newer than the newest or at most 63 behind with its bit clear.

**Request coalescing** (Phase 2.1): Merging many requests for the same expensive work into as few runs as possible. `CrlService` allows one CRL generation in flight; requests that arrive meanwhile set a flag that causes exactly one more run, so 10 concurrent revocations produced 2 new CRLs.

**Root CA** (Phase 1): The top CA in a hierarchy. Its certificate is self-signed and trusted because it was
distributed out of band, not because of a signature. Ours is "CN=VitalsShield Root CA, O=VitalsShield", valid 10
years, published to `var/trust/root-ca.pem`.

**Row lock** (Phase 4): The lock Postgres takes on a row an UPDATE or `SELECT ... FOR UPDATE` touches, held until commit. It serializes concurrent duplicates and the quarantine/ingest race.

**R||S** (Phase 1): The other common ECDSA signature format: r and s each as a fixed 32-byte big-endian number,
concatenated into 64 bytes. JWS (`ES256`) uses this form. KMS returns DER, so a later phase must convert DER to R||S
before putting a KMS signature into a JWS.

**SameSite cookie** (Phase 6): A cookie attribute. `Strict` means the browser sends the cookie only on requests that start from the same site.

**SAN (Subject Alternative Name)** (Phase 1): A certificate extension listing identities the certificate is for:
DNS names, IP addresses, URIs, and more. TLS clients match the hostname against the SAN, not the CN. Our gateway leaf
has `DNS:localhost, IP:127.0.0.1`; our device leaf has `URI:urn:vitalsshield:device:<device_id>`.

**ScheduleKeyDeletion** (Phase 1): The KMS API call that marks a key for deletion after a waiting period of 7 to 30
days. During the wait the key is in state `PendingDeletion` and cannot sign. Our tests use it to simulate key loss.

**Scoped alert retraction** (Phase 4): Retracting only alerts triggered by quarantined batches or drift alerts computed against a tainted baseline version, leaving unrelated alerts active.

**Secure element** (Phase 3): A tamper-resistant chip in a device (for example an ATECC608) that stores keys and signs without exposing them. Our simulated wearable has none, so its DEK is a file that can be copied.

**Self-signed** (Phase 1): A certificate whose issuer and subject are the same and whose signature verifies with its
own public key. Only a Root should be self-signed. Self-signing proves nothing about trust; it only shows the holder
had the key.

**Serial number** (Phase 1): A number, unique per issuer, that identifies a certificate. CRLs list revoked
certificates by serial. Ours are 20 random bytes with the top bit cleared, stored as lowercase hex without leading
zeros.

**Session invalidation** (Phase 2.1): Marking a TLS session as unusable for future connections with `SSLSession.invalidate()`, which also removes it from the JDK server's session cache. Our post-handshake gate does it after every handshake check, so a client can never resume and must do a full handshake each time (DECISIONS #26).

**Session resumption** (Phase 2): Starting a new TLS connection from a previous session's secrets instead of a full handshake. It is faster but skips certificate validation, so a revoked client could get back in; the post-handshake gate closes that gap.

**sessionStorage** (Phase 5): Browser storage scoped to one tab and cleared when it closes. The dashboard keeps the admin setup code there until WebAuthn (DECISIONS #47).

**Setup code** (Phase 4): A random 32-byte bearer token generated at every boot and written to `var/admin/setup-code` (mode 600); the admin API's only authentication until WebAuthn (DECISIONS #41).

**SHA-256** (Phase 0): A hash function with a 32-byte output. We use it for signature digests, SKIs (and so `issuer_key_hash`), and the
fixed-width `sha256(...)` fields inside the canonical encodings.

**Signature counter (signCount)** (Phase 6): A counter the authenticator includes in every assertion, for clone detection. Synced passkeys always send 0; we accept 0 and require any non-zero value to increase (DECISIONS #61).

**SKI (Subject Key Identifier)** (Phase 1): A certificate extension holding an identifier for the certificate's own
public key. A child certificate's AKI equals its issuer's SKI. Ours is the SHA-256 of the full SubjectPublicKeyInfo
DER (32 bytes), and its hex is `issuer_key_hash`.

**SNI (Server Name Indication)** (Phase 2): A field in the TLS ClientHello naming the host the client wants, for example `localhost`. Clients send it with `-servername` in `openssl s_client`; our test client always sends it.

**SPKI (SubjectPublicKeyInfo)** (Phase 1): The ASN.1 structure that holds a public key and its algorithm (for us,
`id-ecPublicKey` on `prime256v1`). KMS `GetPublicKey` returns it as DER, and we put it straight into the certificate.

**SslHandler** (Phase 2): The Netty pipeline component that runs TLS for one channel. Its `handshakeFuture()` completes when the handshake finishes, and its `SSLEngine` session holds the peer certificate. The post-handshake gate listens on it.

**SslProvider** (Phase 2): Netty's choice of TLS implementation: `JDK` (Java's JSSE) or `OPENSSL` (native). We force `JDK` so our Java trust manager is called exactly as JSSE documents.

**Static export** (Phase 5): Next.js `output: "export"`: the build writes plain HTML, JS, and CSS files and no server code runs. The Java server serves `dashboard/out/` on the admin port.

**Step-up authentication** (Phase 6): A fresh approval right before a sensitive action. Here the challenge is a hash of the exact action and its stored parameters, so the approval cannot be reused or swapped (DECISIONS #58).

**Sweep (serial sweep)** (Phase 4): Voiding every RESERVED serial older than 2 minutes, at boot (SERIALS_SWEPT) and on every stale token reclaim, so a crash between signing and activation still ends with a revocable serial.

**TBS (to-be-signed)** (Phase 1): The part of a certificate or CRL that the signature covers: everything except the
signature algorithm field outside it and the signature itself. The builder serializes the TBS to DER and hands those
bytes to the ContentSigner.

**Testcontainers** (Phase 0): A Java library that starts Docker containers from tests and stops them afterwards. Our
schema and PKI integration tests each start a fresh `postgres:16` container, so they never touch the Compose
database.

**TLS 1.3** (Phase 2): The current TLS version (RFC 8446). Compared with 1.2 it encrypts the certificates in the handshake, removes renegotiation and old algorithms, and has one handshake shape. Our TLS listeners accept nothing older.

**TLS alert** (Phase 2): A short TLS message that reports an error and usually ends the connection, such as `certificate_required` (116) or `bad_certificate`. A rejected TLS 1.3 client receives it after finishing its own side of the handshake.

**Trust anchor** (Phase 1): A certificate (usually a Root) that a verifier trusts without checking a signature
above it. Chain validation stops successfully only when it reaches a trust anchor. `TrustAnchors` holds our current
Root and Device Intermediate for the Phase 2 trust manager.

**Trust manager** (Phase 2): The Java object that decides whether a peer's certificate chain is acceptable during a TLS handshake. The JDK calls `checkClientTrusted` when the client's certificate arrives on a full handshake. Ours is `DynamicMtlsTrustManager`.

**UP and UV flags** (Phase 6): authenticatorData bits: user present (someone touched it) and user verified (biometric or PIN). Both are required for every ceremony and re-checked by Protocol A.

**Validity period** (Phase 1): The `notBefore` and `notAfter` times between which a certificate may be accepted. We
set `notBefore` to now minus 60 seconds to absorb clock skew. The Root gets 10 years, intermediates 1 year, device
leaves 12 hours, the gateway leaf 24 hours.

**WebAuthn** (Phase 6): The W3C browser API (`navigator.credentials.create/get`) and protocol for public-key sign-in; the server side is the relying party. We use Yubico java-webauthn-server (DECISIONS #54).

**WebFilter** (Phase 2): A Spring WebFlux component that runs before controllers and can pass the request on or answer it. `PortEnforcementWebFilter` runs first (404 for wrong ports), then `CertStatusResolver` (403 for unaccepted certificates).

**Write-ahead (sequence)** (Phase 4): The simulator persists the next sequence number before sending the batch that uses it, so a crash can never send two different batches with the same number.

**X.509** (Phase 1): The ITU standard format for public key certificates and CRLs, defined in ASN.1. Version 3 added
extensions. RFC 5280 profiles it for internet use.

**-x509_strict** (Phase 1): An `openssl verify` flag that turns on extra RFC 5280 checks that are off by default. For
example, it rejects a non-root certificate without an Authority Key Identifier and a CA certificate without a Subject
Key Identifier. We run every chain check with it so lenient defaults cannot hide a profile mistake.

**x5t#S256** (Phase 3): A JWS header value: base64url SHA-256 of the signer's certificate DER, 43 characters, no padding (RFC 7515). We store exactly this in `certificates.cert_thumbprint_s256` (DECISIONS #35).
