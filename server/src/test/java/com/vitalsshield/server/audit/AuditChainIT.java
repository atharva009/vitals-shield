package com.vitalsshield.server.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.testsupport.TestPorts;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
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

/** Hash chain under pg_advisory_xact_lock (DECISIONS #62). */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuditChainIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-audit-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        TestPorts.registerWebAuthn(registry);
    }

    @Autowired AuditLog audit;
    @Autowired TransactionTemplate tx;
    @Autowired JdbcTemplate jdbc;

    @Test
    @Order(1)
    void fiftyConcurrentAppendsFormOneUnbrokenChain() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            int n = i;
            futures.add(pool.submit(() -> {
                start.await();
                tx.executeWithoutResult(s -> audit.append("TEST_EVENT", "actor_" + (n % 5),
                        Map.of("n", n, "note", "concurrent append", "nested", Map.of("b", 2, "a", "x"))));
                return null;
            }));
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        assertThat(jdbc.queryForObject("SELECT count(*) FROM security_audit_log", Integer.class)).isEqualTo(50);
        assertThat(jdbc.queryForObject("SELECT count(DISTINCT prev_entry_hash) FROM security_audit_log", Integer.class))
                .as("no fork: every prev hash used once").isEqualTo(50);
        AuditLog.Verification v = audit.verify();
        assertThat(v.valid()).isTrue();
        assertThat(v.entries()).isEqualTo(50);
    }

    @Test
    @Order(2)
    void tamperingOnePayloadBreaksTheChainAtThatEntry() {
        long target = jdbc.queryForObject(
                "SELECT sequence_id FROM security_audit_log ORDER BY sequence_id OFFSET 20 LIMIT 1", Long.class);
        // Since V5 (DECISIONS #75) a trigger rejects the UPDATE; the table owner can disable it, which is the
        // tampering the hash chain exists to detect.
        jdbc.execute("ALTER TABLE security_audit_log DISABLE TRIGGER security_audit_log_no_update_delete");
        jdbc.update("UPDATE security_audit_log SET payload_json = jsonb_set(payload_json, '{note}', '\"edited\"') "
                + "WHERE sequence_id = ?", target);
        jdbc.execute("ALTER TABLE security_audit_log ENABLE TRIGGER security_audit_log_no_update_delete");
        AuditLog.Verification v = audit.verify();
        assertThat(v.valid()).isFalse();
        assertThat(v.firstBrokenSequenceId()).isEqualTo(target);
    }
}
