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
     * <p>Returns the process exit code: 0 done, 3 refused or forbidden, 4 the certificate expired (REJECTED
     * cert_expired).
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
            out.println("REJECTED cert_expired serial=" + CertIds.serialDisplay(active.cert()) + " not_after="
                    + active.cert().getNotAfter().toInstant());
            return 4;
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
                byte[] payload = TelemetryFrames.payload(config.deviceId(), state.assignmentId(), state.bootEpoch(),
                        seq, batchId, nb.measuredAt(), sentAt,
                        currentScenario.generate(config.deviceId() + "/" + state.bootEpoch(), seq));
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
                                return 4;
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
                            + currentScenario.cliName() + trustState(r.body()) + (idempotent ? " idempotent" : ""));
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
                        if (active.expiredAt(clock.instant())) {
                            out.println("REJECTED cert_expired serial=" + CertIds.serialDisplay(active.cert()));
                            return 4;
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
