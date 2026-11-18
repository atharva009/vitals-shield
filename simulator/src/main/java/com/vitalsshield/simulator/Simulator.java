package com.vitalsshield.simulator;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.vitalsshield.crypto.CsrFactory;
import com.vitalsshield.crypto.DerSignatures;
import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.crypto.encoding.CanonicalEncodings;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/** A simulated wearable: Protocol A enrollment, Protocol B renewal, persistence, streaming and the mTLS ping. */
public final class Simulator {

    /**
     * A stored certificate valid for at least this long counts as enrolled; no HTTP call is made. Changed in Phase 8
     * from 5 minutes: Protocol B now renews a leaf before it expires, and the demo leaf lives about 3 minutes
     * (DECISIONS #83), so any unexpired leaf with a little time left is renewed by {@code run}, not re-enrolled.
     */
    static final Duration MIN_REMAINING_VALIDITY = Duration.ofSeconds(30);

    public record Config(String deviceId, Path stateRoot, Path trustFile, URI publicUrl, URI mtlsUrl) {
    }

    public sealed interface EnrollOutcome {
        record AlreadyEnrolled(X509Certificate cert) implements EnrollOutcome {
        }

        record Enrolled(X509Certificate cert, long bootEpoch) implements EnrollOutcome {
        }

        record Failed(int status, String body) implements EnrollOutcome {
        }
    }

    private final Config config;
    private final SimulatorStateStore store;
    private final Clock clock;

    public Simulator(Config config, Clock clock) {
        this.config = config;
        this.store = new SimulatorStateStore(config.stateRoot(), config.deviceId());
        this.clock = clock;
    }

    public SimulatorStateStore store() {
        return store;
    }

    public EnrollOutcome enroll(String token) throws IOException, InterruptedException {
        Optional<SimulatorStateStore.Enrollment> existing = store.load();
        if (existing.isPresent() && existing.get().olkCert().getNotAfter().toInstant()
                .isAfter(clock.instant().plus(MIN_REMAINING_VALIDITY))) {
            return new EnrollOutcome.AlreadyEnrolled(existing.get().olkCert());
        }

        KeyPair dek = store.loadOrCreateDek();      // survives a state reset
        KeyPair olk = EcKeys.generateP256();        // fresh every enrollment
        byte[] csr = CsrFactory.create(olk, config.deviceId());
        Map<String, Object> body = enrollmentBody(config.deviceId(), token, dek, csr);

        GatewayClient.Response r = GatewayClient.publicClient(config.trustFile())
                .postJson(config.publicUrl().resolve("/api/v1/devices/enroll"), JSONObjectUtils.toJSONString(body));
        if (r.status() != 201) {
            return new EnrollOutcome.Failed(r.status(), r.body());
        }
        Map<String, Object> json = parse(r.body());
        String certPem = (String) json.get("new_cert_pem");
        long bootEpoch = ((Number) json.get("assigned_boot_epoch")).longValue();
        // measured_at stays monotonic across re-enrollment when the old state is still there (DECISIONS #74).
        String lastMeasuredAt = existing.map(x -> x.state().lastMeasuredAt()).orElse(null);
        SimulatorState state = new SimulatorState(config.deviceId(), bootEpoch, 0,
                (String) json.get("current_assignment_id"), (String) json.get("assignment_active_from"),
                clock.instant().toString(), lastMeasuredAt);
        store.saveEnrollment(olk.getPrivate(), certPem, state);
        return new EnrollOutcome.Enrolled(SimulatorStateStore.parseCert(certPem), bootEpoch);
    }

    /** The JSON body of POST /api/v1/devices/enroll, with the DEK proof over (device_id, token, CSR). */
    public static Map<String, Object> enrollmentBody(String deviceId, String token, KeyPair dek, byte[] csrDer) {
        byte[] proof = DerSignatures.sign(dek.getPrivate(),
                CanonicalEncodings.dekEnrollmentProofBytes(deviceId, token, csrDer));
        Base64.Encoder b64 = Base64.getEncoder();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("device_id", deviceId);
        body.put("bootstrap_token", token);
        body.put("dek_spki_der_b64", b64.encodeToString(EcKeys.spkiDer(dek.getPublic())));
        body.put("olk_csr_der_b64", b64.encodeToString(csrDer));
        body.put("dek_proof_sig_b64", b64.encodeToString(proof));
        return body;
    }

    /** GET /api/v1/telemetry/ping with the certificate stream would use (a valid pending one first). */
    public GatewayClient.Response ping() throws IOException, InterruptedException {
        Optional<SimulatorStateStore.Pending> p = store.loadPending();
        SimulatorStateStore.Enrollment e = store.load()
                .orElseThrow(() -> new IllegalStateException("not enrolled: run enroll first"));
        PrivateKey key = e.olkKey();
        X509Certificate cert = e.olkCert();
        if (p.isPresent() && Identity.of(p.get().key(), p.get().cert()).validAt(clock.instant())) {
            key = p.get().key();
            cert = p.get().cert();
        }
        try (GatewayClient c = GatewayClient.mtlsClient(config.trustFile(), key, cert)) {
            return c.get(config.mtlsUrl().resolve("/api/v1/telemetry/ping"));
        }
    }

    /**
     * Scenario control for {@link #stream}: {@code start} (null: the scenario file, else resting) and an optional
     * script. The scenario file is read before every batch; a value written by someone else (the {@code scenario}
     * command) takes over and ends the script.
     */
    public record StreamOptions(Scenario start, ScenarioScript script) {
        public static final StreamOptions DEFAULT = new StreamOptions(null, null);
    }

    public int stream(long intervalMs, long count, java.io.PrintStream out) throws InterruptedException {
        return stream(intervalMs, count, out, StreamOptions.DEFAULT);
    }

    /** A key and its certificate: what the mTLS client presents and what signs each frame. */
    record Identity(PrivateKey key, X509Certificate cert, byte[] der) {
        static Identity of(PrivateKey key, X509Certificate cert) {
            try {
                return new Identity(key, cert, cert.getEncoded());
            } catch (java.security.cert.CertificateEncodingException e) {
                throw new IllegalStateException(e);
            }
        }

        boolean expiredAt(Instant now) {
            return !cert.getNotAfter().toInstant().isAfter(now);
        }

        boolean validAt(Instant now) {
            return !now.isBefore(cert.getNotBefore().toInstant()) && !expiredAt(now);
        }
    }

    /** Protocol B outcome. */
    public sealed interface RenewOutcome {
        record Renewed(SimulatorStateStore.Pending pending, String assignmentId) implements RenewOutcome {
        }

        record Failed(int status, String code, Long retryAfterSeconds) implements RenewOutcome {
        }
    }

    /**
     * Protocol B over {@code client}, which presents {@code current} (the ACTIVE certificate): GET a challenge, make a
     * new OLK and CSR, sign the proof (spec encoding 5) with the current OLK, POST /renew. On 200 the new key and
     * certificate are persisted as pending before they are used (DECISIONS #85), and the assignment from the response
     * is stored.
     */
    public RenewOutcome renew(GatewayClient client, PrivateKey currentKey, X509Certificate currentCert)
            throws IOException, InterruptedException {
        GatewayClient.Response ch = client.get(config.mtlsUrl().resolve("/api/v1/devices/renew-challenge"));
        if (ch.status() != 200) {
            return failed(ch);
        }
        Map<String, Object> c = parse(ch.body());
        KeyPair olk = EcKeys.generateP256();
        byte[] csr = CsrFactory.create(olk, config.deviceId());
        Map<String, Object> body = renewalBody(CertIds.issuerKeyHash(currentCert), CertIds.serial(currentCert),
                ((Number) c.get("issued_at_ms")).longValue(),
                Base64.getDecoder().decode((String) c.get("random_nonce_b64")), (String) c.get("hmac_tag_b64"), csr,
                currentKey);
        GatewayClient.Response r = client.postJson(config.mtlsUrl().resolve("/api/v1/devices/renew"),
                JSONObjectUtils.toJSONString(body));
        if (r.status() != 200) {
            return failed(r);
        }
        Map<String, Object> json = parse(r.body());
        String pem = (String) json.get("new_cert_pem");
        store.savePending(olk.getPrivate(), pem);
        String assignmentId = (String) json.get("current_assignment_id");
        store.updateAssignment(assignmentId, (String) json.get("assignment_active_from"));
        return new RenewOutcome.Renewed(new SimulatorStateStore.Pending(olk.getPrivate(),
                SimulatorStateStore.parseCert(pem)), assignmentId);
    }

    /** The JSON body of POST /api/v1/devices/renew; the proof is signed by {@code signer} (the current OLK). */
    public static Map<String, Object> renewalBody(String issuerKeyHash, String serial, long issuedAtMs, byte[] nonce,
                                                  String hmacTagB64, byte[] newCsrDer, PrivateKey signer) {
        byte[] proof = DerSignatures.sign(signer,
                CanonicalEncodings.olkRenewalProofBytes(issuerKeyHash, serial, issuedAtMs, nonce, newCsrDer));
        Base64.Encoder b64 = Base64.getEncoder();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("issuer_key_hash", issuerKeyHash);
        body.put("serial_number", serial);
        body.put("issued_at_ms", issuedAtMs);
        body.put("random_nonce_b64", b64.encodeToString(nonce));
        body.put("hmac_tag_b64", hmacTagB64);
        body.put("olk_new_csr_der_b64", b64.encodeToString(newCsrDer));
        body.put("olk_renewal_sig_b64", b64.encodeToString(proof));
        return body;
    }

    private static RenewOutcome.Failed failed(GatewayClient.Response r) {
        String code = "HTTP_" + r.status();
        try {
            Object e = parse(r.body()).get("error");
            if (e instanceof String s) {
                code = s;
            }
        } catch (RuntimeException ignored) {
            // non-JSON body: keep HTTP_<status>
        }
        return new RenewOutcome.Failed(r.status(), code,
                r.headers().firstValue("Retry-After").map(Long::parseLong).orElse(null));
    }

    /** Protocol C outcome (DECISIONS #95). */
    public sealed interface ReEnrollOutcome {
        record ReEnrolled(X509Certificate cert, long bootEpoch, long previousEpoch) implements ReEnrollOutcome {
        }

        /** 409 REAUTH_REQUIRED, BOOT_EPOCH_INVALID, BOOT_EPOCH_REGRESSION, or 403 DEVICE_NOT_ACTIVE: exit 5. */
        record Reauth(int status, String code) implements ReEnrollOutcome {
        }

        record Failed(int status, String code, Long retryAfterSeconds) implements ReEnrollOutcome {
        }
    }

    /** Re-enrollment answers that mean a clinician has to act (exit 5). */
    static final java.util.Set<String> REAUTH_CODES = java.util.Set.of("REAUTH_REQUIRED", "BOOT_EPOCH_INVALID",
            "BOOT_EPOCH_REGRESSION", "DEVICE_NOT_ACTIVE");

    /**
     * Protocol C over the public port (spec Section 4): GET /challenge?device_id=, a new OLK and CSR, the DEK signs
     * (device_id, issued_at_ms, nonce, stored boot_epoch, sha256(csr)), POST /re-enroll. On 200 the new key, certificate,
     * assigned epoch and assignment are persisted (atomic renames) before anything uses them.
     */
    public ReEnrollOutcome reEnroll() throws IOException, InterruptedException {
        SimulatorStateStore.Enrollment e = store.load()
                .orElseThrow(() -> new IllegalStateException("no device state: Protocol C needs the stored boot_epoch"));
        Optional<KeyPair> dek = store.loadDek();
        if (dek.isEmpty()) {
            return new ReEnrollOutcome.Failed(0, "NO_DEK", null); // factory-wiped: only Protocol A can help
        }
        long epoch = e.state().bootEpoch();
        try (GatewayClient pub = GatewayClient.publicClient(config.trustFile())) {
            GatewayClient.Response ch = pub.get(config.publicUrl().resolve("/api/v1/devices/challenge?device_id="
                    + java.net.URLEncoder.encode(config.deviceId(), java.nio.charset.StandardCharsets.UTF_8)));
            if (ch.status() != 200) {
                return reEnrollFailed(ch);
            }
            Map<String, Object> c = parse(ch.body());
            KeyPair olk = EcKeys.generateP256();
            byte[] csr = CsrFactory.create(olk, config.deviceId());
            Map<String, Object> body = reEnrollBody(config.deviceId(), ((Number) c.get("issued_at_ms")).longValue(),
                    Base64.getDecoder().decode((String) c.get("random_nonce_b64")), (String) c.get("hmac_tag_b64"),
                    epoch, csr, dek.get().getPrivate());
            GatewayClient.Response r = pub.postJson(config.publicUrl().resolve("/api/v1/devices/re-enroll"),
                    JSONObjectUtils.toJSONString(body));
            if (r.status() != 200) {
                return reEnrollFailed(r);
            }
            Map<String, Object> json = parse(r.body());
            String pem = (String) json.get("new_cert_pem");
            long assigned = ((Number) json.get("assigned_boot_epoch")).longValue();
            store.saveReEnrollment(olk.getPrivate(), pem, assigned, (String) json.get("current_assignment_id"),
                    (String) json.get("assignment_active_from"));
            return new ReEnrollOutcome.ReEnrolled(SimulatorStateStore.parseCert(pem), assigned, epoch);
        }
    }

    /** The JSON body of POST /api/v1/devices/re-enroll; {@code dekKey} signs reEnrollProofBytes. */
    public static Map<String, Object> reEnrollBody(String deviceId, long issuedAtMs, byte[] nonce, String hmacTagB64,
                                                   long bootEpoch, byte[] csrDer, PrivateKey dekKey) {
        byte[] proof = DerSignatures.sign(dekKey,
                CanonicalEncodings.reEnrollProofBytes(deviceId, issuedAtMs, nonce, bootEpoch, csrDer));
        Base64.Encoder b64 = Base64.getEncoder();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("device_id", deviceId);
        body.put("issued_at_ms", issuedAtMs);
        body.put("random_nonce_b64", b64.encodeToString(nonce));
        body.put("hmac_tag_b64", hmacTagB64);
        body.put("boot_epoch", bootEpoch);
        body.put("olk_csr_der_b64", b64.encodeToString(csrDer));
        body.put("dek_sig_b64", b64.encodeToString(proof));
        return body;
    }

    private static ReEnrollOutcome reEnrollFailed(GatewayClient.Response r) {
        RenewOutcome.Failed f = failed(r);
        if ((r.status() == 409 || r.status() == 403) && REAUTH_CODES.contains(f.code())) {
            return new ReEnrollOutcome.Reauth(r.status(), f.code());
        }
        return new ReEnrollOutcome.Failed(f.status(), f.code(), f.retryAfterSeconds());
    }

    /** Transient Protocol C failures (503, 429, I/O) are retried this many times before giving up with exit 4. */
    static final int REENROLL_ATTEMPTS = 5;

    /**
     * Automatic recovery after cert_expired (DECISIONS #95). Returns null on success (the new identity is on disk), or
     * the exit code: 5 if a clinician must act, 4 if re-enrollment is impossible (no DEK, rejected proof, ...).
     */
    Integer recoverByReEnroll(java.io.PrintStream out, String reason) throws InterruptedException {
        for (int attempt = 1; ; attempt++) {
            ReEnrollOutcome o;
            try {
                o = reEnroll();
            } catch (IOException io) {
                o = new ReEnrollOutcome.Failed(0, "IO_" + io.getClass().getSimpleName(), null);
            }
            switch (o) {
                case ReEnrollOutcome.ReEnrolled r -> {
                    out.println("RE-ENROLLED serial=" + CertIds.serialDisplay(r.cert()) + " boot_epoch="
                            + r.bootEpoch() + " reason=" + reason
                            + (r.bootEpoch() != r.previousEpoch() ? " previous_boot_epoch=" + r.previousEpoch() : "")
                            + " at=" + clock.instant());
                    return null;
                }
                case ReEnrollOutcome.Reauth a -> {
                    out.println("REAUTH_REQUIRED code=" + a.code());
                    return 5;
                }
                case ReEnrollOutcome.Failed f -> {
                    boolean transientFailure = f.status() == 0 && f.code().startsWith("IO_") || f.status() == 503
                            || f.status() == 429;
                    out.println("RE_ENROLL_FAILED status=" + f.status() + " error=" + f.code() + " attempt=" + attempt);
                    if (!transientFailure || attempt >= REENROLL_ATTEMPTS) {
                        return 4;
                    }
                    Thread.sleep(1000L * (f.retryAfterSeconds() != null ? f.retryAfterSeconds() : 2));
                }
            }
        }
    }

    /** After a failed renewal, wait this long (or the server's Retry-After) before the next attempt. */
    static final Duration RENEW_RETRY = Duration.ofSeconds(5);

    /**
     * Streaming mode: one signed batch every {@code intervalMs} ({@code count} batches, 0 = forever). The sequence
     * number and the compressed-clock measured_at are persisted before each send (write-ahead, DECISIONS #74).
     *
     * <p>Renewal (Protocol B, DECISIONS #83, #85, #86): before each batch, if the current certificate is past 2/3 of
     * its validity (or the last batch got 409 ASSIGNMENT_CHANGED), renew over the current certificate, switch to a new
     * client with the pending certificate from the next batch, and promote it to current after its first 200. A failed
     * renewal is logged and streaming continues on the current certificate.
     *
     * <p>Protocol C (DECISIONS #95): when the certificate has expired (at launch with no valid pending certificate, a
     * 403 with reason EXPIRED or OUTSIDE_VALIDITY, or a refused handshake past not_after), the simulator re-enrolls
     * with the DEK and its stored boot_epoch, prints RE-ENROLLED, and sends the same frame again with the new key.
     *
     * <p>Returns the process exit code: 0 done, 3 refused or forbidden (a revoked certificate is never recovered), 4
     * the certificate expired and re-enrollment was impossible, 5 a clinician must act (REAUTH_REQUIRED or an epoch
     * rejection).
     */
    public int stream(long intervalMs, long count, java.io.PrintStream out, StreamOptions options)
            throws InterruptedException {
        Optional<SimulatorStateStore.Pending> pendingOnDisk = store.loadPending(); // may finish a promotion
        SimulatorStateStore.Enrollment e = store.load()
                .orElseThrow(() -> new IllegalStateException("not enrolled: run enroll first"));
        Identity current = Identity.of(e.olkKey(), e.olkCert());
        Identity active = current;
        boolean usingPending = false;
        if (pendingOnDisk.isPresent()) {
            Identity p = Identity.of(pendingOnDisk.get().key(), pendingOnDisk.get().cert());
            if (p.validAt(clock.instant())) {                 // DECISIONS #85: a valid pending one is preferred
                active = p;
                usingPending = true;
                out.println("USING_PENDING serial=" + CertIds.serialDisplay(p.cert()));
            }
        }
        if (active.expiredAt(clock.instant())) {
            // DECISIONS #95: expired while the device was off, and no valid pending certificate: Protocol C.
            out.println("REJECTED cert_expired serial=" + CertIds.serialDisplay(active.cert()) + " not_after="
                    + active.cert().getNotAfter().toInstant());
            Integer exit = recoverByReEnroll(out, "cert_expired");
            if (exit != null) {
                return exit;
            }
            SimulatorStateStore.Enrollment fresh = store.load().orElseThrow();
            current = Identity.of(fresh.olkKey(), fresh.olkCert());
            active = current;
            usingPending = false;
        }
        GatewayClient client = GatewayClient.mtlsClient(config.trustFile(), active.key(), active.cert());
        URI ingest = config.mtlsUrl().resolve("/api/v1/telemetry/ingest");
        long lastOkSeq = 0;
        long lastOkAt = System.nanoTime();
        boolean renewNow = false;
        Instant nextRenewAttempt = Instant.MIN;

        ScenarioScript script = options.script();
        Scenario currentScenario = options.start() != null ? options.start()
                : script != null ? script.at(0) : store.readScenario().orElse(Scenario.RESTING);
        store.writeScenario(currentScenario);
        Scenario lastWritten = currentScenario;
        out.println("SCENARIO " + currentScenario.cliName());

        try {
            for (long sent = 0; count == 0 || sent < count; sent++) {
                Scenario fromFile = store.readScenario().orElse(lastWritten);
                Scenario next = currentScenario;
                if (fromFile != lastWritten) {                // `simulator scenario --set` while running
                    script = null;
                    next = fromFile;
                    lastWritten = fromFile;
                } else if (script != null) {
                    next = script.at(sent);
                    if (next != lastWritten) {
                        store.writeScenario(next);
                        lastWritten = next;
                    }
                }
                if (next != currentScenario) {
                    currentScenario = next;
                    out.println("SCENARIO " + currentScenario.cliName());
                }

                // Renewal check before each batch. It always presents the current (server-side ACTIVE) certificate.
                Instant now = clock.instant();
                boolean due = !usingPending && RenewalDueRule.isDue(current.cert(), now);
                if ((renewNow || due) && !now.isBefore(nextRenewAttempt) && !current.expiredAt(now)) {
                    renewNow = false;
                    GatewayClient renewClient = usingPending
                            ? GatewayClient.mtlsClient(config.trustFile(), current.key(), current.cert()) : client;
                    RenewOutcome ro;
                    try {
                        ro = renew(renewClient, current.key(), current.cert());
                    } catch (IOException io) {
                        ro = new RenewOutcome.Failed(0, "IO_" + io.getClass().getSimpleName(), null);
                    } finally {
                        if (renewClient != client) {
                            renewClient.close();
                        }
                    }
                    if (ro instanceof RenewOutcome.Renewed r) {
                        out.println("RENEWED old=" + CertIds.serialDisplay(current.cert()) + " new="
                                + CertIds.serialDisplay(r.pending().cert()) + " due_at="
                                + RenewalDueRule.dueAt(current.cert()) + " at=" + clock.instant());
                        active = Identity.of(r.pending().key(), r.pending().cert());
                        usingPending = true;
                        client.close();                       // the next batch handshakes with the pending cert
                        client = GatewayClient.mtlsClient(config.trustFile(), active.key(), active.cert());
                    } else if (ro instanceof RenewOutcome.Failed f) {
                        out.println("RENEW_FAILED status=" + f.status() + " error=" + f.code());
                        nextRenewAttempt = clock.instant().plus(f.retryAfterSeconds() != null
                                ? Duration.ofSeconds(f.retryAfterSeconds()) : RENEW_RETRY);
                    }
                }

                SimulatorStateStore.NextBatch nb = store.nextBatch(clock.instant()); // persisted before use
                long seq = nb.sequenceNumber();
                SimulatorState state = store.load().orElseThrow().state();
                java.util.UUID batchId = java.util.UUID.randomUUID();
                Instant sentAt = clock.instant();
                var metrics = currentScenario.generate(config.deviceId() + "/" + state.bootEpoch(), seq);
                byte[] payload = TelemetryFrames.payload(config.deviceId(), state.assignmentId(), state.bootEpoch(),
                        seq, batchId, nb.measuredAt(), sentAt, metrics);
                String jws = com.vitalsshield.crypto.TelemetryJws.sign(payload, active.key(), active.der());

                while (true) {                                // same frame until it is answered (DECISIONS #44)
                    long t0 = System.nanoTime();
                    GatewayClient.Response r;
                    try {
                        r = client.postJose(ingest, jws);
                    } catch (IOException io) {
                        if (GatewayClient.isHandshakeRefused(io)) {
                            if (active.expiredAt(clock.instant())) {
                                out.println("REJECTED cert_expired serial=" + CertIds.serialDisplay(active.cert())
                                        + " not_after=" + active.cert().getNotAfter().toInstant() + " last_ok_seq="
                                        + lastOkSeq);
                                Integer exit = recoverByReEnroll(out, "cert_expired");
                                if (exit != null) {
                                    return exit;
                                }
                                client.close();
                                SimulatorStateStore.Enrollment fresh = store.load().orElseThrow();
                                current = Identity.of(fresh.olkKey(), fresh.olkCert());
                                active = current;
                                usingPending = false;
                                client = GatewayClient.mtlsClient(config.trustFile(), active.key(), active.cert());
                                // The same frame (sequence number, batch id) again, signed by the new key.
                                SimulatorState st = fresh.state();
                                jws = com.vitalsshield.crypto.TelemetryJws.sign(TelemetryFrames.payload(
                                        config.deviceId(), st.assignmentId(), st.bootEpoch(), seq, batchId,
                                        nb.measuredAt(), sentAt, metrics), active.key(), active.der());
                                continue;
                            }
                            out.println("REJECTED handshake_refused last_ok_seq=" + lastOkSeq + " ms_since_last_ok="
                                    + (System.nanoTime() - lastOkAt) / 1_000_000);
                            return 3;
                        }
                        Thread.sleep(1000);                   // broken connection: the client reconnects on retry
                        continue;
                    }
                    long rtt = (System.nanoTime() - t0) / 1_000_000;
                    boolean idempotent = r.body() != null && r.body().contains("\"idempotent_retry\":true");
                    out.println("SENT seq=" + seq + " batch=" + batchId.toString().substring(0, 8) + " status="
                            + r.status() + " rtt_ms=" + rtt + " measured_at=" + nb.measuredAt() + " scenario="
                            + currentScenario.cliName() + trustState(r.body()) + (idempotent ? " idempotent" : "")
                            + (r.status() == 200 ? "" : " error=" + failed(r).code()));
                    if (r.status() == 503) {
                        Thread.sleep(1000L * r.headers().firstValue("Retry-After").map(Long::parseLong).orElse(1L));
                        continue;
                    }
                    if (r.status() == 200) {
                        lastOkSeq = seq;
                        lastOkAt = System.nanoTime();
                        if (usingPending) {                   // first 200 with the pending cert (DECISIONS #85)
                            store.promotePending();
                            current = active;
                            usingPending = false;
                            out.println("ACTIVATED new=" + CertIds.serialDisplay(active.cert()) + " at="
                                    + clock.instant());
                        }
                    } else if (r.status() == 403) {
                        String reason = rejectReason(r.body());
                        boolean expired = "EXPIRED".equals(reason) || "OUTSIDE_VALIDITY".equals(reason)
                                || (reason == null && active.expiredAt(clock.instant()));
                        if (expired) {
                            // DECISIONS #95: cert_expired is recoverable with the DEK. A revoked certificate is not.
                            out.println("REJECTED cert_expired serial=" + CertIds.serialDisplay(active.cert())
                                    + (reason == null ? "" : " reason=" + reason));
                            Integer exit = recoverByReEnroll(out, "cert_expired");
                            if (exit != null) {
                                return exit;
                            }
                            client.close();
                            SimulatorStateStore.Enrollment fresh = store.load().orElseThrow();
                            current = Identity.of(fresh.olkKey(), fresh.olkCert());
                            active = current;
                            usingPending = false;
                            client = GatewayClient.mtlsClient(config.trustFile(), active.key(), active.cert());
                            SimulatorState st = fresh.state();
                            jws = com.vitalsshield.crypto.TelemetryJws.sign(TelemetryFrames.payload(
                                    config.deviceId(), st.assignmentId(), st.bootEpoch(), seq, batchId,
                                    nb.measuredAt(), sentAt, metrics), active.key(), active.der());
                            continue;
                        }
                        out.println(r.body());
                        return 3;
                    } else if (r.status() == 409 && r.body() != null && r.body().contains("ASSIGNMENT_CHANGED")) {
                        Map<String, Object> json = parse(r.body());
                        String id = (String) json.get("current_assignment_id");
                        store.updateAssignment(id, (String) json.get("assignment_active_from"));
                        out.println("ASSIGNMENT_CHANGED new=" + id + " renewing");
                        renewNow = true;                      // DECISIONS #86
                        nextRenewAttempt = Instant.MIN;
                    } else if (r.status() != 409) {
                        out.println(r.body());
                    }
                    break;
                }
                if (intervalMs > 0 && (count == 0 || sent + 1 < count)) {
                    Thread.sleep(intervalMs);
                }
            }
        } finally {
            client.close();
        }
        return 0;
    }

    /** The "reason" of a 403 CERT_NOT_ACCEPTED body, or null. */
    static String rejectReason(String body) {
        if (body == null) {
            return null;
        }
        try {
            Object v = parse(body).get("reason");
            return v instanceof String str ? str : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String trustState(String body) {
        if (body == null) {
            return "";
        }
        int i = body.indexOf("\"trust_state\":\"");
        if (i < 0) {
            return "";
        }
        int from = i + "\"trust_state\":\"".length();
        int to = body.indexOf('"', from);
        return to < 0 ? "" : " trust_state=" + body.substring(from, to);
    }

    private static Map<String, Object> parse(String json) {
        try {
            return JSONObjectUtils.parse(json);
        } catch (ParseException e) {
            throw new IllegalStateException("unexpected response: " + json, e);
        }
    }

    static Instant notAfter(X509Certificate c) {
        return c.getNotAfter().toInstant();
    }
}
