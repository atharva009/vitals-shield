package com.vitalsshield.server.testsupport;

import com.vitalsshield.crypto.TelemetryJws;
import com.vitalsshield.devtools.DevSeeder;
import com.vitalsshield.simulator.Simulator;
import com.vitalsshield.simulator.SimulatorStateStore;
import com.vitalsshield.simulator.TelemetryFrames;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/** Seed + in-process simulator enrollment + signed telemetry frames, for ingest, quarantine, and e2e tests. */
public final class SpineFixture {

    public record Device(String deviceId, Simulator sim, SimulatorStateStore.Enrollment enrollment) {
        public X509Certificate cert() {
            return enrollment.olkCert();
        }

        public String assignmentId() {
            return enrollment.state().assignmentId();
        }

        public long bootEpoch() {
            return enrollment.state().bootEpoch();
        }
    }

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final TestPorts.Listeners ports;
    private final Path trustFile;
    private final Path stateRoot;

    public SpineFixture(JdbcTemplate jdbc, TransactionTemplate tx, TestPorts.Listeners ports, Path trustFile,
                        Path stateRoot) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.ports = ports;
        this.trustFile = trustFile;
        this.stateRoot = stateRoot;
    }

    public Simulator simulator(String deviceId) {
        return new Simulator(new Simulator.Config(deviceId, stateRoot, trustFile,
                URI.create("https://127.0.0.1:" + ports.pub()), URI.create("https://127.0.0.1:" + ports.mtls())),
                Clock.systemUTC());
    }

    /** Bearer mode: a dev seed token with fake WebAuthn fields. */
    public Device enroll(String deviceId) {
        return enrollWithToken(deviceId,
                new DevSeeder(jdbc, tx, Clock.systemUTC()).seed(DevSeeder.Request.defaults(deviceId)).token());
    }

    /** Any mode: enroll with a token issued elsewhere (webauthn mode: provisioned through the admin API). */
    public Device enrollWithToken(String deviceId, String token) {
        Simulator sim = simulator(deviceId);
        try {
            Simulator.EnrollOutcome o = sim.enroll(token);
            if (!(o instanceof Simulator.EnrollOutcome.Enrolled)) {
                throw new IllegalStateException("enrollment failed: " + o);
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
        return new Device(deviceId, sim, sim.store().load().orElseThrow());
    }

    /** A signed frame with resting metrics, measured and transmitted now. */
    public static String frame(Device d, long seq, UUID batchId) {
        Instant now = Instant.now();
        return frame(d, seq, batchId, now, TelemetryFrames.Metrics.resting(new Random(seq)), d.assignmentId(), d.bootEpoch());
    }

    public static String frame(Device d, long seq, UUID batchId, Instant measuredAt, TelemetryFrames.Metrics m,
                               String assignmentId, long bootEpoch) {
        byte[] payload = TelemetryFrames.payload(d.deviceId(), assignmentId, bootEpoch, seq, batchId, measuredAt,
                Instant.now(), m);
        try {
            return TelemetryJws.sign(payload, d.enrollment().olkKey(), d.cert().getEncoded());
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    public MtlsTestClient.Connection connect(Device d, X509Certificate root) throws IOException {
        return MtlsTestClient.connect(ports.mtls(), root, d.enrollment().olkKey(), List.of(d.cert()));
    }

    public static MtlsTestClient.Response ingest(MtlsTestClient.Connection c, String jws) throws IOException {
        return c.post("/api/v1/telemetry/ingest", "application/jose", jws);
    }

    public String adminBearer(Path setupCodeFile) {
        try {
            return "Bearer " + java.nio.file.Files.readString(setupCodeFile).trim();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
