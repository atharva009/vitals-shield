package com.vitalsshield.server.renewal;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.simulator.CertIds;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.nio.file.Files;
import java.nio.file.Path;
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
 * DECISIONS #86: mid-stream the assignment is closed and a new one opened. The in-process simulator gets 409
 * ASSIGNMENT_CHANGED, stores the new assignment id, renews at once, and continues on the new assignment with the new
 * certificate.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class AssignmentChangedRenewalIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-assign-renew-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;

    SpineFixture fx() {
        return new SpineFixture(jdbc, tx, ports, dir.resolve("root-ca.pem"), dir.resolve("sim"));
    }

    @Test
    void assignmentChangeTriggersRenewal() throws Exception {
        SpineFixture.Device d = fx().enroll("dev_assign_renew");
        String oldAssignment = d.assignmentId();
        String oldSerial = CertIds.serial(d.cert());
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(buf, true, StandardCharsets.UTF_8);
        CompletableFuture<Integer> run = CompletableFuture.supplyAsync(() -> {
            try {
                return d.sim().stream(300, 20, out);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return -1;
            }
        });
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        while (jdbc.queryForObject("SELECT count(*) FROM telemetry_records WHERE device_id = ?", Integer.class,
                d.deviceId()) < 4) {
            assertThat(System.nanoTime()).as("first batches").isLessThan(deadline);
            Thread.sleep(50);
        }
        UUID newAssignment = UUID.randomUUID();
        tx.executeWithoutResult(s -> {
            jdbc.update("""
                    UPDATE patient_device_assignments SET status = 'CLOSED', active_until = NOW()
                     WHERE device_id = ? AND status = 'ACTIVE'
                    """, d.deviceId());
            jdbc.update("""
                    INSERT INTO patient_device_assignments (assignment_id, device_id, patient_id, patient_birth_year,
                                                            active_from, max_renewal_horizon, status)
                    VALUES (?, ?, 'patient-reassigned', 1979, NOW(), NOW() + INTERVAL '30 days', 'ACTIVE')
                    """, newAssignment, d.deviceId());
        });
        assertThat(run.get(60, TimeUnit.SECONDS)).isZero();
        String log = buf.toString(StandardCharsets.UTF_8);
        System.out.println(log);

        assertThat(log).contains("ASSIGNMENT_CHANGED new=" + newAssignment);
        int changed = log.indexOf("ASSIGNMENT_CHANGED");
        int renewed = log.indexOf("RENEWED old=");
        int activated = log.indexOf("ACTIVATED new=");
        assertThat(renewed).as("renewal right after the 409").isGreaterThan(changed);
        assertThat(activated).isGreaterThan(renewed);
        // Exactly one batch was refused with 409 (the one signed for the old assignment); the rest are 200.
        assertThat(log.lines().filter(l -> l.startsWith("SENT") && !l.contains("status=200")).toList())
                .hasSize(1).allMatch(l -> l.contains("status=409"));

        List<Map<String, Object>> certs = jdbc.queryForList("""
                SELECT serial_number, status::text AS status, superseded_serial FROM certificates
                 WHERE device_id = ? ORDER BY issued_at
                """, d.deviceId());
        assertThat(certs).hasSize(2);
        assertThat(certs.get(0)).containsEntry("serial_number", oldSerial).containsEntry("status", "RENEWED");
        assertThat(certs.get(1)).containsEntry("status", "ACTIVE").containsEntry("superseded_serial", oldSerial);
        String newSerial = (String) certs.get(1).get("serial_number");
        // Batches after the change carry the new assignment and are signed by the new certificate.
        assertThat(jdbc.queryForObject("""
                SELECT count(*) FROM telemetry_records
                 WHERE device_id = ? AND assignment_id = ? AND serial_number <> ?
                """, Integer.class, d.deviceId(), newAssignment, newSerial)).isZero();
        assertThat(jdbc.queryForObject("""
                SELECT count(*) FROM telemetry_records WHERE device_id = ? AND assignment_id = ?
                """, Integer.class, d.deviceId(), newAssignment)).isGreaterThan(5);
        assertThat(jdbc.queryForObject("""
                SELECT count(*) FROM telemetry_records WHERE device_id = ? AND assignment_id = ?::uuid
                """, Integer.class, d.deviceId(), oldAssignment)).isGreaterThanOrEqualTo(4);
        assertThat(d.sim().store().load().orElseThrow().state().assignmentId()).isEqualTo(newAssignment.toString());
    }
}
