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
