package com.vitalsshield.server.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.crypto.TelemetryJws;
import com.vitalsshield.server.anomaly.AnomalyProperties;
import com.vitalsshield.server.clinical.ClinicalProperties;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.reenroll.ReEnrollProperties;
import com.vitalsshield.server.testsupport.LedgerInvariant;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.SimulatorState;
import com.vitalsshield.simulator.SimulatorStateStore;
import com.vitalsshield.simulator.TelemetryFrames;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * False-positive guard (DECISIONS 100). The demo profile with every trap ON, and only what a genuine device does:
 * about 4 minutes of streaming with many Protocol B rollovers, 5 idempotent retries of one frame, an offline pause past
 * not_after with Protocol C recovery, then 30 more batches. Not one SECURITY_ANOMALY_ALERT is allowed.
 *
 * <p>TTL PT100S (a leaf lives about 40 s and renews about 7 s after issuance, so 4 minutes contain dozens of
 * rollovers) and grace PT5S override the demo profile's PT4M/PT60S to keep the test short. Old certificates are never
 * probed: that is a clone's behavior, not a device's.
 */
@Tag("e2e")
@Testcontainers
@ActiveProfiles("demo")
@SpringBootTest
class NormalOperationNoAnomalyE2E {

    static final String DEV = "dev_e2e_normal";

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-normal-e2e");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        registry.add("vitalsshield.pki.leaf-ttl", () -> "PT100S");
        registry.add("vitalsshield.pki.renewal-grace", () -> "PT5S");
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    @Autowired AnomalyProperties anomaly;
    @Autowired ReEnrollProperties reenroll;
    @Autowired ClinicalProperties clinical;

    @Test
    void normalDeviceBehaviorRaisesNoAnomaly() throws Exception {
        // The demo profile is what is running (DECISIONS 99), traps included.
        assertThat(anomaly.sequenceRegression().enabled()).isTrue();
        assertThat(anomaly.postDrain().enabled()).isTrue();
        assertThat(reenroll.perAddressLimit()).isEqualTo(60);
        assertThat(reenroll.globalLimit()).isEqualTo(300);
        assertThat(clinical.calibrationSize()).isEqualTo(10);

        SpineFixture.Device d = new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"))
                .enroll(DEV);
        List<String> all = new ArrayList<>();

        // 1. About 4 minutes of streaming, with rollovers.
        String first = stream(d, 1000, 240);
        all.addAll(first.lines().toList());
        long renewed = first.lines().filter(l -> l.startsWith("RENEWED ")).count();
        long activated = first.lines().filter(l -> l.startsWith("ACTIVATED ")).count();
        System.out.println("NORMAL_OPERATION phase=stream batches=240 renewed=" + renewed + " activated=" + activated);
        assertThat(renewed).isGreaterThanOrEqualTo(2);
        assertThat(activated).isGreaterThanOrEqualTo(2);

        // 2. Five idempotent retries: one frame, its sequence number allocated through the simulator's own store (so
        // the stream continues after it), sent six times on the current certificate.
        SimulatorStateStore store = d.sim().store();
        SimulatorStateStore.Enrollment e = store.load().orElseThrow();
        SimulatorStateStore.NextBatch nb = store.nextBatch(Instant.now());
        SimulatorState st = store.load().orElseThrow().state();
        String jws = frame(e.olkKey(), e.olkCert(), st, nb);
        int idempotent = 0;
        try (MtlsTestClient.Connection c = MtlsTestClient.connect(ports.mtls(), anchors.root(), e.olkKey(),
                List.of(e.olkCert()))) {
            for (int i = 0; i < 6; i++) {
                MtlsTestClient.Response r = SpineFixture.ingest(c, jws);
                assertThat(r.status()).as(r.body()).isEqualTo(200);
                if (r.body().contains("\"idempotent_retry\":true")) {
                    idempotent++;
                }
            }
        }
        System.out.println("NORMAL_OPERATION phase=retries seq=" + nb.sequenceNumber() + " idempotent=" + idempotent);
        assertThat(idempotent).isEqualTo(5);

        // 3. Offline past not_after (the pending certificate too, if a renewal was in flight), then resume.
        Instant until = latestNotAfter(store);
        Thread.sleep(Math.max(0, Duration.between(Instant.now(), until).toMillis()) + 1000);
        String second = stream(d, 300, 30);
        all.addAll(second.lines().toList());
        System.out.println("NORMAL_OPERATION phase=resume " + second.lines().filter(l -> l.startsWith("RE-ENROLLED")
                || l.startsWith("REJECTED")).toList());
        assertThat(second).contains("RE-ENROLLED serial=").contains("reason=cert_expired");
        assertThat(second.lines().filter(l -> l.startsWith("SENT "))).hasSize(30);

        // Assertions (DECISIONS 100).
        List<String> non200 = all.stream().filter(l -> l.startsWith("SENT ") && !l.contains("status=200")).toList();
        long expiredRejections = all.stream().filter(l -> l.startsWith("REJECTED cert_expired")).count();
        long anomalies = jdbc.queryForObject("SELECT count(*) FROM clinical_alerts "
                + "WHERE alert_type = 'SECURITY_ANOMALY_ALERT'", Long.class);
        String state = jdbc.queryForObject("SELECT trust_state::text FROM devices WHERE device_id = ?", String.class,
                DEV);
        long renewals = jdbc.queryForObject("SELECT count(*) FROM certificates WHERE device_id = ? "
                + "AND issued_via = 'RENEW'", Long.class, DEV);
        long reEnrollments = jdbc.queryForObject("SELECT count(*) FROM certificates WHERE device_id = ? "
                + "AND issued_via = 'REENROLL'", Long.class, DEV);
        int ledger = LedgerInvariant.violations(jdbc);
        System.out.println("NORMAL_OPERATION summary batches_sent=" + all.stream().filter(l -> l.startsWith("SENT "))
                .count() + " non200=" + non200.size() + " cert_expired_rejections=" + expiredRejections
                + " renewals=" + renewals + " reenrollments=" + reEnrollments + " idempotent_retries=" + idempotent
                + " security_anomaly_alerts=" + anomalies + " trust_state=" + state + " ledger_violations=" + ledger);

        assertThat(anomalies).as("SECURITY_ANOMALY_ALERT rows").isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM security_audit_log WHERE event_type = 'SECURITY_ANOMALY'",
                Long.class)).isZero();
        assertThat(state).isEqualTo("ACTIVE");
        // The one expected refusal is cert_expired before recovery: the simulator notices it at launch (no request)
        // or gets a single 403 for it; nothing else may fail.
        assertThat(expiredRejections).isEqualTo(1);
        assertThat(non200).hasSizeLessThanOrEqualTo(1).allMatch(l -> l.contains("status=403"));
        assertThat(reEnrollments).isEqualTo(1);
        assertThat(ledger).isZero();
    }

    String stream(SpineFixture.Device d, long intervalMs, int count) throws InterruptedException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int exit = d.sim().stream(intervalMs, count, new PrintStream(buf, true, StandardCharsets.UTF_8));
        String out = buf.toString(StandardCharsets.UTF_8);
        assertThat(exit).as(out).isZero();
        return out;
    }

    static String frame(PrivateKey key, X509Certificate cert, SimulatorState st, SimulatorStateStore.NextBatch nb)
            throws Exception {
        byte[] payload = TelemetryFrames.payload(DEV, st.assignmentId(), st.bootEpoch(), nb.sequenceNumber(),
                UUID.randomUUID(), nb.measuredAt(), Instant.now(), TelemetryFrames.Metrics.resting(new Random(7)));
        return TelemetryJws.sign(payload, key, cert.getEncoded());
    }

    static Instant latestNotAfter(SimulatorStateStore store) {
        Instant current = store.load().orElseThrow().olkCert().getNotAfter().toInstant();
        Instant pending = store.loadPending().map(p -> p.cert().getNotAfter().toInstant()).orElse(Instant.MIN);
        return current.isAfter(pending) ? current : pending;
    }
}
