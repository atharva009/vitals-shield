package com.vitalsshield.server.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.quarantine.QuarantineService;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.CertIds;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
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
 * Protocol B end to end: the in-process simulator streams one batch per second for about 75 s and renews on its own
 * at 2/3 of each leaf's validity. TTL PT2M (a PT40S leaf would already be expired at issuance, because notBefore is
 * backdated 60 s), grace PT3S. Then a quarantine revokes everything and the simulator exits 3.
 */
@Tag("e2e")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class RenewalE2E {

    static final String DEV = "dev_e2e_renew";
    static final byte[] PROBE = "key matches certificate".getBytes(StandardCharsets.US_ASCII);

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-renewal-e2e");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        registry.add("vitalsshield.pki.leaf-ttl", () -> "PT2M");
        registry.add("vitalsshield.pki.renewal-grace", () -> "PT3S");
        // This test presents every old certificate long after its grace, on purpose, to prove the handshake refuses
        // it. That is exactly what the post-drain trap (DECISIONS #94) treats as a clone; PostDrainTrapIT covers it.
        registry.add("vitalsshield.anomaly.post-drain.enabled", () -> "false");
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;
    @Autowired QuarantineService quarantine;

    record Seen(PrivateKey key, X509Certificate cert) {
    }

    @Test
    void streamsThroughRolloversThenQuarantineEndsIt() throws Exception {
        SpineFixture fx = new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"));
        SpineFixture.Device d = fx.enroll(DEV);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(buf, true, StandardCharsets.UTF_8);
        Instant start = Instant.now();
        CompletableFuture<Integer> run = CompletableFuture.supplyAsync(() -> {
            try {
                return d.sim().stream(1000, 0, out);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return -1;
            }
        });

        // Collect every key/certificate pair the simulator holds (old keys are deleted on promotion), so each old
        // certificate's handshake can be tried after its grace.
        Map<String, Seen> seen = new LinkedHashMap<>();
        Path keyFile = d.sim().store().olkKeyFile();
        Path certFile = d.sim().store().olkCertFile();
        while (Duration.between(start, Instant.now()).toSeconds() < 75) {
            try {
                X509Certificate c = parse(Files.readString(certFile));
                PrivateKey k = EcKeys.fromPkcs8Pem(Files.readString(keyFile));
                if (com.vitalsshield.crypto.DerSignatures.verify(c.getPublicKey(), PROBE,
                        com.vitalsshield.crypto.DerSignatures.sign(k, PROBE))) {
                    seen.putIfAbsent(CertIds.serial(c), new Seen(k, c));
                }
            } catch (RuntimeException | IOException midRename) {
                // a promotion was renaming the files; read again
            }
            assertThat(run.isDone()).as("simulator still streaming: " + buf).isFalse();
            Thread.sleep(100);
        }
        String streamed = buf.toString(StandardCharsets.UTF_8);

        // Every RENEWED certificate whose grace has passed is refused at the handshake.
        List<Map<String, Object>> certs = jdbc.queryForList("""
                SELECT serial_number, status::text AS status, issued_at, activated_at, grace_expires_at, not_before,
                       not_after FROM certificates WHERE device_id = ? ORDER BY issued_at
                """, DEV);
        int refused = 0;
        for (Map<String, Object> c : certs) {
            Timestamp grace = (Timestamp) c.get("grace_expires_at");
            // A superseded certificate is RENEWED until its not_after, then the sweeper marks it EXPIRED.
            boolean pastGrace = grace != null && grace.toInstant().isBefore(Instant.now())
                    && ("RENEWED".equals(c.get("status")) || "EXPIRED".equals(c.get("status")));
            if (pastGrace) {
                Seen s = seen.get((String) c.get("serial_number"));
                assertThat(s).as("key for " + c.get("serial_number")).isNotNull();
                MtlsTestClient.Attempt a = MtlsTestClient.attempt(ports.mtls(), anchors.root(), s.key(),
                        List.of(s.cert()), "/api/v1/telemetry/ping");
                assertThat(a.kind()).as(c.get("serial_number") + " after grace").isEqualTo(MtlsTestClient.Kind.TLS_REJECTED);
                refused++;
            }
        }

        // Final quarantine: everything revoked, the simulator stops with exit code 3.
        QuarantineService.Result q = quarantine.quarantine(DEV, 5, "renewal e2e end").block(Duration.ofSeconds(20));
        int exit = run.get(30, TimeUnit.SECONDS);
        String all = buf.toString(StandardCharsets.UTF_8);
        System.out.println(all);

        List<String> renewedLines = streamed.lines().filter(l -> l.startsWith("RENEWED ")).toList();
        List<String> activatedLines = streamed.lines().filter(l -> l.startsWith("ACTIVATED ")).toList();
        List<String> sent = streamed.lines().filter(l -> l.startsWith("SENT ")).toList();
        List<String> non200 = sent.stream().filter(l -> !l.contains("status=200")).toList();

        // Rollover timings from the database.
        System.out.println("ROLLOVER_TIMINGS");
        Instant prevIssued = null;
        for (Map<String, Object> c : certs) {
            Instant issued = ((Timestamp) c.get("issued_at")).toInstant();
            Timestamp act = (Timestamp) c.get("activated_at");
            Timestamp grace = (Timestamp) c.get("grace_expires_at");
            System.out.printf("  serial=%s status=%s issued=%s since_prev_issue=%s issue_to_activation_ms=%s "
                            + "grace_expires=%s lifetime_after_issue=%s%n",
                    CertIds.serialDisplay(seenOrParse(seen, c)), c.get("status"), issued,
                    prevIssued == null ? "-" : Duration.between(prevIssued, issued).toMillis() + "ms",
                    act == null ? "-" : Duration.between(issued, act.toInstant()).toMillis(),
                    grace == null ? "-" : grace.toInstant(),
                    Duration.between(issued, ((Timestamp) c.get("not_after")).toInstant()).toSeconds() + "s");
            prevIssued = issued;
        }
        System.out.println("ROLLOVERS renewed=" + renewedLines.size() + " activated=" + activatedLines.size()
                + " batches=" + sent.size() + " non200=" + non200.size() + " old_certs_refused_after_grace="
                + refused + " quarantine_revoked=" + q.certsRevoked() + " exit=" + exit);

        assertThat(renewedLines).as("RENEWED lines").hasSizeGreaterThanOrEqualTo(2);
        assertThat(activatedLines).as("ACTIVATED lines").hasSizeGreaterThanOrEqualTo(2);
        assertThat(non200).as("non-200 batch responses while streaming").isEmpty();
        assertThat(sent.size()).isGreaterThanOrEqualTo(60);
        assertThat(refused).as("old certificates tried after grace").isEqualTo(renewedLines.size());
        assertThat(q.certsRevoked()).isGreaterThanOrEqualTo(1);
        assertThat(jdbc.queryForObject("""
                SELECT count(*) FROM certificates WHERE device_id = ? AND status IN ('ACTIVE', 'ISSUED_PENDING_USE')
                """, Integer.class, DEV)).isZero();
        assertThat(exit).isEqualTo(3);
    }

    private static X509Certificate seenOrParse(Map<String, Seen> seen, Map<String, Object> row) {
        Seen s = seen.get((String) row.get("serial_number"));
        if (s != null) {
            return s.cert();
        }
        throw new IllegalStateException("no certificate captured for " + row.get("serial_number"));
    }

    private static X509Certificate parse(String pem) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
        } catch (java.security.cert.CertificateException e) {
            throw new IllegalStateException(e);
        }
    }
}
