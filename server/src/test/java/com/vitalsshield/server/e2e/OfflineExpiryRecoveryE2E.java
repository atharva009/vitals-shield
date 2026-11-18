package com.vitalsshield.server.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.quarantine.QuarantineService;
import com.vitalsshield.server.testsupport.LedgerInvariant;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
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
 * The Phase 8 laptop-sleep incident, recovered automatically (DECISIONS #95, #97): the in-process simulator streams,
 * stops (the laptop sleeps), its leaf expires, and on resume it re-enrolls with the DEK, keeps its boot_epoch and
 * sequence numbers, and streams on with no clinician action. A final quarantine still ends it with exit 3.
 *
 * <p>Leaf TTL PT100S, not PT80S: notBefore is backdated 60 s, so a PT80S leaf is already due for renewal (2/3 of the
 * validity) when it is issued and the simulator would renew before every batch. PT100S lives about 40 s and is due
 * about 7 s after issuance, so the 3-second bursts below never renew (DECISIONS #83).
 */
@Tag("e2e")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class OfflineExpiryRecoveryE2E {

    static final String DEV = "dev_e2e_offline";

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-offline-e2e");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        registry.add("vitalsshield.pki.leaf-ttl", () -> "PT100S");
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired QuarantineService quarantine;

    @Test
    void streamSleepPastNotAfterResumeReEnrollsAutomatically() throws Exception {
        SpineFixture.Device d = new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"))
                .enroll(DEV);
        Instant t0 = Instant.now();
        System.out.println("OFFLINE_TIMELINE enrolled serial=" + d.cert().getSerialNumber().toString(16).toUpperCase()
                + " not_after=" + d.cert().getNotAfter().toInstant() + " at=" + t0);

        ByteArrayOutputStream before = new ByteArrayOutputStream();
        assertThat(d.sim().stream(300, 10, new PrintStream(before, true, StandardCharsets.UTF_8))).isZero();
        List<String> sentBefore = sent(before);
        assertThat(sentBefore).hasSize(10).allMatch(l -> l.contains("status=200"));
        System.out.println("OFFLINE_TIMELINE streamed seq=1..10 until=" + Instant.now());

        // The laptop sleeps past not_after.
        Instant notAfter = d.cert().getNotAfter().toInstant();
        Thread.sleep(Math.max(0, Duration.between(Instant.now(), notAfter).toMillis()) + 1000);
        System.out.println("OFFLINE_TIMELINE woke at=" + Instant.now() + " (" + Duration.between(notAfter,
                Instant.now()).toMillis() + " ms after not_after)");

        ByteArrayOutputStream after = new ByteArrayOutputStream();
        assertThat(d.sim().stream(300, 10, new PrintStream(after, true, StandardCharsets.UTF_8))).isZero();
        String afterText = after.toString(StandardCharsets.UTF_8);
        afterText.lines().filter(l -> !l.startsWith("SENT ") || l.contains("seq=11 ") || l.contains("seq=20 "))
                .forEach(l -> System.out.println("OFFLINE_TIMELINE " + l));
        assertThat(afterText).contains("REJECTED cert_expired").contains("RE-ENROLLED serial=")
                .contains("boot_epoch=1 reason=cert_expired");
        List<String> sentAfter = sent(after);
        assertThat(sentAfter).hasSize(10).allMatch(l -> l.contains("status=200"));
        assertThat(sentAfter.get(0)).startsWith("SENT seq=11 ");
        assertThat(sentAfter.get(9)).startsWith("SENT seq=20 ");

        Map<String, Object> device = jdbc.queryForMap("SELECT trust_state::text AS ts, boot_epoch, last_sequence_num "
                + "FROM devices WHERE device_id = ?", DEV);
        assertThat(device).containsEntry("ts", "ACTIVE").containsEntry("boot_epoch", 1L)
                .containsEntry("last_sequence_num", 20L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM security_audit_log WHERE payload_json->>'device_id' = ?",
                Long.class, DEV)).as("no clinician action, no anomaly").isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM clinical_alerts WHERE device_id = ? "
                + "AND alert_type = 'SECURITY_ANOMALY_ALERT'", Long.class, DEV)).isZero();
        assertThat(LedgerInvariant.violations(jdbc)).isZero();
        Map<String, Object> reenrolled = jdbc.queryForMap("SELECT issued_at, reenroll_reason FROM certificates "
                + "WHERE device_id = ? AND issued_via = 'REENROLL'", DEV);
        System.out.println("OFFLINE_TIMELINE db reenroll issued_at=" + reenrolled.get("issued_at") + " reason="
                + reenrolled.get("reenroll_reason"));

        // A final quarantine still works: the simulator is refused and exits 3.
        ByteArrayOutputStream last = new ByteArrayOutputStream();
        CompletableFuture<Integer> run = CompletableFuture.supplyAsync(() -> {
            try {
                return d.sim().stream(300, 0, new PrintStream(last, true, StandardCharsets.UTF_8));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return -1;
            }
        });
        Thread.sleep(1500);
        QuarantineService.Result q = quarantine.quarantine(DEV, 5, "offline e2e end").block(Duration.ofSeconds(20));
        int exit = run.get(30, TimeUnit.SECONDS);
        System.out.println("OFFLINE_TIMELINE quarantine certs_revoked=" + q.certsRevoked() + " batches_quarantined="
                + q.batchesQuarantined() + " exit=" + exit);
        assertThat(q.certsRevoked()).isGreaterThanOrEqualTo(1);
        assertThat(exit).isEqualTo(3);
    }

    static List<String> sent(ByteArrayOutputStream buf) {
        return buf.toString(StandardCharsets.UTF_8).lines().filter(l -> l.startsWith("SENT ")).toList();
    }
}
