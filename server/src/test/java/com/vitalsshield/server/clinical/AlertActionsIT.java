package com.vitalsshield.server.clinical;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.devtools.DevSeeder;
import com.vitalsshield.server.admin.webauthn.ProvisioningRecords;
import com.vitalsshield.server.admin.webauthn.RegistryAnchorKey;
import com.vitalsshield.server.audit.AuditLog;
import com.vitalsshield.server.testsupport.AdminHttp;
import com.vitalsshield.server.testsupport.SoftwareAuthenticator;
import com.vitalsshield.server.testsupport.TestPorts;
import com.vitalsshield.server.testsupport.WebAuthnSteps;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
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

/** DECISIONS #76: acknowledge and resolve need a passkey session, follow the allowed transitions, and are audited. */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class AlertActionsIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path dir;
    static final SoftwareAuthenticator ALICE = SoftwareAuthenticator.create();
    static AdminHttp alice;
    static UUID assignment;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        dir = Files.createTempDirectory("vs-alerts-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.registerWebAuthn(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired AuditLog audit;
    @Autowired RegistryAnchorKey anchorKey;

    @BeforeEach
    void setUp() {
        if (alice == null) {
            alice = new AdminHttp(ports.admin());
            WebAuthnSteps.bootstrapClinician(alice, ALICE, "dr_alice", ports.adminCodeFile());
            assignment = tx.execute(s -> new ProvisioningRecords(jdbc).ensureDeviceAndAssignment("dev_alerts", "sim",
                    "p", 1985, 30, Instant.now())).id();
        }
    }

    UUID alert(String status) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO clinical_alerts (alert_id, device_id, assignment_id, alert_type, alert_status,
                                             triggering_batch_ids, explanation_summary, condition_code, retracted_at)
                VALUES (?, 'dev_alerts', ?, 'ACUTE_PHYSIOLOGICAL_ALERT', ?::alert_lifecycle_status, '{}', 'test', 'SPO2_LOW',
                        CASE WHEN ? = 'RETRACTED_BY_QUARANTINE' THEN NOW() END)
                """, id, assignment, status, status);
        return id;
    }

    String status(UUID id) {
        return jdbc.queryForObject("SELECT alert_status::text FROM clinical_alerts WHERE alert_id = ?", String.class, id);
    }

    AdminHttp.Response act(AdminHttp h, UUID id, String action) {
        return h.post("/api/v1/admin/alerts/" + id + "/" + action, "{}");
    }

    long auditCount(String event) {
        return jdbc.queryForObject("SELECT count(*) FROM security_audit_log WHERE event_type = ?", Long.class, event);
    }

    @Test
    void acknowledgeThenResolve() {
        UUID a = alert("ACTIVE");
        AdminHttp.Response ack = act(alice, a, "acknowledge");
        assertThat(ack.status()).as(ack.body()).isEqualTo(200);
        assertThat(ack.json()).containsEntry("alert_status", "ACKNOWLEDGED").containsEntry("by", "dr_alice");
        assertThat(act(alice, a, "acknowledge").status()).as("ACKNOWLEDGED -> ACKNOWLEDGED").isEqualTo(409);
        AdminHttp.Response res = act(alice, a, "resolve");
        assertThat(res.status()).as(res.body()).isEqualTo(200);
        assertThat(status(a)).isEqualTo("RESOLVED");
        AdminHttp.Response again = act(alice, a, "resolve");
        assertThat(again.status()).isEqualTo(409);
        assertThat(again.body()).contains("ILLEGAL_TRANSITION").contains("RESOLVED");
        assertThat(act(alice, a, "acknowledge").status()).as("RESOLVED is final").isEqualTo(409);

        Map<String, Object> entry = jdbc.queryForMap("""
                SELECT actor_id, payload_json::text AS p FROM security_audit_log
                 WHERE event_type = 'ALERT_RESOLVED' ORDER BY sequence_id DESC LIMIT 1
                """);
        assertThat(entry.get("actor_id")).isEqualTo("dr_alice");
        assertThat((String) entry.get("p")).contains(a.toString()).contains("\"from\": \"ACKNOWLEDGED\"")
                .contains("\"to\": \"RESOLVED\"");
        assertThat(audit.verify().valid()).isTrue();
    }

    @Test
    void activeCanBeResolvedDirectly() {
        UUID a = alert("ACTIVE");
        long before = auditCount("ALERT_RESOLVED");
        assertThat(act(alice, a, "resolve").status()).isEqualTo(200);
        assertThat(status(a)).isEqualTo("RESOLVED");
        assertThat(auditCount("ALERT_RESOLVED")).isEqualTo(before + 1);
    }

    @Test
    void retractedAlertCannotChange() {
        UUID a = alert("RETRACTED_BY_QUARANTINE");
        long before = jdbc.queryForObject("SELECT count(*) FROM security_audit_log", Long.class);
        assertThat(act(alice, a, "acknowledge").status()).isEqualTo(409);
        assertThat(act(alice, a, "resolve").status()).isEqualTo(409);
        assertThat(status(a)).isEqualTo("RETRACTED_BY_QUARANTINE");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM security_audit_log", Long.class))
                .as("refusals are not audited as actions").isEqualTo(before);
    }

    @Test
    void unknownAlertIs404AndBadIdIs400() {
        assertThat(act(alice, UUID.randomUUID(), "acknowledge").status()).isEqualTo(404);
        assertThat(alice.post("/api/v1/admin/alerts/not-a-uuid/acknowledge", "{}").status()).isEqualTo(400);
    }

    @Test
    void noSessionNoAction() {
        UUID a = alert("ACTIVE");
        AdminHttp anonymous = new AdminHttp(ports.admin());
        assertThat(act(anonymous, a, "acknowledge").status()).isEqualTo(401);
        assertThat(anonymous.post("/api/v1/admin/alerts/" + a + "/resolve", "{}", null, null).status())
                .as("no Origin header").isEqualTo(403);
        assertThat(status(a)).isEqualTo("ACTIVE");
    }

    @Test
    void devSeedPasskeyCannotAct() {
        Path keyFile = dir.resolve("devseed/passkey.key");
        DevSeeder.seedWebAuthn(jdbc, tx, Clock.systemUTC(), anchorKey, keyFile, ports.admin(), Set.of("local"),
                DevSeeder.Request.defaults("dev_alerts_seed"));
        UUID a = alert("ACTIVE");
        AdminHttp seed = new AdminHttp(ports.admin());
        AdminHttp.Response in = WebAuthnSteps.signIn(seed, SoftwareAuthenticator.load(keyFile));
        assertThat(in.status()).as(in.body()).isEqualTo(403);
        assertThat(seed.cookie()).as("DEV_SEED gets no session").isNull();
        assertThat(act(seed, a, "acknowledge").status()).isEqualTo(401);
        assertThat(act(seed, a, "resolve").status()).isEqualTo(401);
        assertThat(status(a)).isEqualTo("ACTIVE");
    }

    @Test
    @SuppressWarnings("unchecked")
    void alertListAndOverviewCounts() {
        UUID a = alert("ACTIVE");
        AdminHttp.Response all = alice.get("/api/v1/admin/alerts");
        assertThat(all.status()).as(all.body()).isEqualTo(200);
        assertThat(all.body()).contains(a.toString());
        AdminHttp.Response filtered = alice.get("/api/v1/admin/alerts?device_id=dev_alerts&limit=5");
        assertThat(filtered.status()).isEqualTo(200);
        assertThat(filtered.body()).contains("\"device_id\":\"dev_alerts\"").contains("\"triggering_batch_count\":0");
        AdminHttp.Response none = alice.get("/api/v1/admin/alerts?device_id=dev_nobody");
        assertThat(none.body()).isEqualTo("[]");
        Map<String, Object> overview = alice.get("/api/v1/admin/overview").json();
        Map<String, Object> counts = (Map<String, Object>) overview.get("alerts");
        assertThat(((Number) counts.get("active")).longValue()).isGreaterThanOrEqualTo(1);
        assertThat(overview.get("clinical")).asString().contains("calibration_size=10");
    }
}
