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
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/** A simulated wearable: Protocol A enrollment, persistence, and the mTLS ping. */
public final class Simulator {

    /** A stored certificate valid for at least this long counts as enrolled; no HTTP call is made. */
    static final Duration MIN_REMAINING_VALIDITY = Duration.ofMinutes(5);

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
        SimulatorState state = new SimulatorState(config.deviceId(), bootEpoch, 0,
                (String) json.get("current_assignment_id"), (String) json.get("assignment_active_from"),
                clock.instant().toString());
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

    public GatewayClient.Response ping() throws IOException, InterruptedException {
        SimulatorStateStore.Enrollment e = store.load()
                .orElseThrow(() -> new IllegalStateException("not enrolled: run enroll first"));
        return GatewayClient.mtlsClient(config.trustFile(), e.olkKey(), e.olkCert())
                .get(config.mtlsUrl().resolve("/api/v1/telemetry/ping"));
    }

    /**
     * Streaming mode: one signed batch every {@code intervalMs} ({@code count} batches, 0 = forever). The sequence
     * number is persisted before each send (write-ahead). Returns the process exit code (0 done, 3 refused/forbidden).
     */
    public int stream(long intervalMs, long count, java.io.PrintStream out) throws InterruptedException {
        SimulatorStateStore.Enrollment e = store.load()
                .orElseThrow(() -> new IllegalStateException("not enrolled: run enroll first"));
        if (!e.olkCert().getNotAfter().toInstant().isAfter(clock.instant())) {
            throw new IllegalStateException("stored certificate has expired: enroll again");
        }
        byte[] certDer;
        try {
            certDer = e.olkCert().getEncoded();
        } catch (java.security.cert.CertificateEncodingException ex) {
            throw new IllegalStateException(ex);
        }
        GatewayClient client = GatewayClient.mtlsClient(config.trustFile(), e.olkKey(), e.olkCert());
        URI ingest = config.mtlsUrl().resolve("/api/v1/telemetry/ingest");
        java.util.Random rnd = new java.util.Random();
        long lastOkSeq = 0;
        long lastOkAt = System.nanoTime();

        for (long sent = 0; count == 0 || sent < count; sent++) {
            long seq = store.incrementSequence();             // persisted before use
            SimulatorState state = store.load().orElseThrow().state();
            java.util.UUID batchId = java.util.UUID.randomUUID();
            Instant now = clock.instant();
            byte[] payload = TelemetryFrames.payload(config.deviceId(), state.assignmentId(), state.bootEpoch(), seq,
                    batchId, now, now, TelemetryFrames.Metrics.resting(rnd));
            String jws = com.vitalsshield.crypto.TelemetryJws.sign(payload, e.olkKey(), certDer);

            while (true) {                                    // same frame until it is answered (DECISIONS #44)
                long t0 = System.nanoTime();
                GatewayClient.Response r;
                try {
                    r = client.postJose(ingest, jws);
                } catch (IOException io) {
                    if (GatewayClient.isHandshakeRefused(io)) {
                        out.println("REJECTED handshake_refused last_ok_seq=" + lastOkSeq + " ms_since_last_ok="
                                + (System.nanoTime() - lastOkAt) / 1_000_000);
                        return 3;
                    }
                    Thread.sleep(1000);                       // broken connection: the client reconnects on retry
                    continue;
                }
                long rtt = (System.nanoTime() - t0) / 1_000_000;
                boolean idempotent = r.body() != null && r.body().contains("\"idempotent_retry\":true");
                out.println("SENT seq=" + seq + " batch=" + batchId.toString().substring(0, 8) + " status=" + r.status()
                        + " rtt_ms=" + rtt + (idempotent ? " idempotent" : ""));
                if (r.status() == 503) {
                    Thread.sleep(1000L * r.headers().firstValue("Retry-After").map(Long::parseLong).orElse(1L));
                    continue;
                }
                if (r.status() == 200) {
                    lastOkSeq = seq;
                    lastOkAt = System.nanoTime();
                } else if (r.status() == 403) {
                    out.println(r.body());
                    return 3;
                } else if (r.status() == 409 && r.body() != null && r.body().contains("ASSIGNMENT_CHANGED")) {
                    Map<String, Object> json = parse(r.body());
                    store.updateAssignment((String) json.get("current_assignment_id"),
                            (String) json.get("assignment_active_from"));
                } else if (r.status() != 409) {
                    out.println(r.body());
                }
                break;
            }
            if (intervalMs > 0 && (count == 0 || sent + 1 < count)) {
                Thread.sleep(intervalMs);
            }
        }
        return 0;
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
