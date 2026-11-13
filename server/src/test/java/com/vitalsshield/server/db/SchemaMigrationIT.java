package com.vitalsshield.server.db;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.SQLException;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Boots the server context against a throwaway postgres:16 container (one per class); Flyway applies V1 on startup.
 * Each test uses its own device/issuer IDs so tests stay independent within the shared container.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class SchemaMigrationIT {

    @Container
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @Autowired
    JdbcTemplate jdbc;

    @Test
    void migratesCleanly() {
        List<String> tables = jdbc.queryForList(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'", String.class);

        assertThat(tables).contains(
                "clinician_passkeys",
                "ca_issuers",
                "devices",
                "device_bootstrap_tokens",
                "consumed_challenge_nonces",
                "certificates",
                "patient_device_assignments",
                "telemetry_records",
                "clinical_alerts",
                "security_audit_log",
                "kms_keys");
    }

    @Test
    void oneActiveKeyPerPurpose() {
        insertKmsKey("arn:aws:kms:us-east-1:000000000000:key/root-1", "ACTIVE");

        assertSqlState(() -> insertKmsKey("arn:aws:kms:us-east-1:000000000000:key/root-2", "ACTIVE"), "23505");

        insertKmsKey("arn:aws:kms:us-east-1:000000000000:key/root-old", "RETIRED");
        assertThat(jdbc.queryForObject(
                "SELECT count(*) FROM kms_keys WHERE purpose = 'ROOT_CA'", Integer.class)).isEqualTo(2);
    }

    @Test
    void oneActiveCertPerDevice() {
        String issuer = insertIssuer("issuer-cert-test");
        String device = insertDevice("device-cert-test");

        insertActiveCert(issuer, "serial-1", device);
        assertSqlState(() -> insertActiveCert(issuer, "serial-2", device), "23505");
    }

    @Test
    void assignmentOverlapRejected() {
        String device = insertDevice("device-assignment-test");
        // The first row is CLOSED so that idx_one_active_assignment_per_device (23505) cannot fire; only the
        // EXCLUDE constraint on overlapping [active_from, active_until) can reject the second insert.
        jdbc.update("""
                INSERT INTO patient_device_assignments
                    (assignment_id, device_id, patient_id, patient_birth_year,
                     active_from, active_until, max_renewal_horizon, status)
                VALUES (?, ?, 'patient-a', 1970,
                        '2026-01-01T00:00:00Z', '2026-01-10T00:00:00Z', '2026-02-01T00:00:00Z', 'CLOSED')
                """, UUID.randomUUID(), device);

        assertSqlState(() -> jdbc.update("""
                INSERT INTO patient_device_assignments
                    (assignment_id, device_id, patient_id, patient_birth_year,
                     active_from, active_until, max_renewal_horizon, status)
                VALUES (?, ?, 'patient-b', 1980,
                        '2026-01-05T00:00:00Z', NULL, '2026-02-01T00:00:00Z', 'ACTIVE')
                """, UUID.randomUUID(), device), "23P01");
    }

    @Test
    void driftAlertNeedsBaselineVersion() {
        String device = insertDevice("device-alert-test");

        assertSqlState(() -> insertAlert(device, "POTENTIAL_PHYSIOLOGICAL_DRIFT", null), "23514");
        assertSqlState(() -> insertAlert(device, "ACUTE_PHYSIOLOGICAL_ALERT", 1), "23514");
    }

    private void insertKmsKey(String arn, String status) {
        jdbc.update("INSERT INTO kms_keys (kms_key_id, purpose, status) "
                + "VALUES (?, 'ROOT_CA', ?::kms_key_status)", arn, status);
    }

    private String insertIssuer(String keyHash) {
        jdbc.update("""
                INSERT INTO ca_issuers (issuer_key_hash, subject_dn, kms_primary_arn, cert_pem, status)
                VALUES (?, 'CN=VitalsShield Issuing CA G1, O=VitalsShield',
                        'arn:aws:kms:us-east-1:000000000000:key/intermediate', 'PEM', 'ACTIVE')
                """, keyHash);
        return keyHash;
    }

    private String insertDevice(String deviceId) {
        jdbc.update("INSERT INTO devices (device_id, hardware_model) VALUES (?, 'sim-v1')", deviceId);
        return deviceId;
    }

    private void insertActiveCert(String issuer, String serial, String device) {
        jdbc.update("""
                INSERT INTO certificates
                    (issuer_key_hash, serial_number, device_id, cert_thumbprint_s256, cert_pem,
                     not_before, not_after, status)
                VALUES (?, ?, ?, 'thumb', 'PEM', NOW(), NOW() + INTERVAL '12 hours', 'ACTIVE')
                """, issuer, serial, device);
    }

    private void insertAlert(String device, String type, Integer baselineVersion) {
        jdbc.update("""
                INSERT INTO clinical_alerts
                    (alert_id, device_id, baseline_version, alert_type, triggering_batch_ids, explanation_summary)
                VALUES (?, ?, ?, ?::alert_severity_type, ARRAY[?]::uuid[], 'test')
                """, UUID.randomUUID(), device, baselineVersion, type, UUID.randomUUID());
    }

    private static void assertSqlState(Runnable statement, String expectedSqlState) {
        assertThatThrownBy(statement::run)
                .isInstanceOf(DataAccessException.class)
                .satisfies(e -> {
                    Throwable cause = NestedExceptionUtils.getMostSpecificCause(e);
                    assertThat(cause).isInstanceOf(SQLException.class);
                    assertThat(((SQLException) cause).getSQLState()).isEqualTo(expectedSqlState);
                });
    }
}
