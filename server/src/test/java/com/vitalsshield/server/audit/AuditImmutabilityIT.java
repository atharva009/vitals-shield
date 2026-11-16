package com.vitalsshield.server.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import com.vitalsshield.server.testsupport.TestPorts;

/** DECISIONS #75: security_audit_log is append-only in the database, and no application SQL edits it. */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class AuditImmutabilityIT {

    static final String MESSAGE = "security_audit_log is append-only";

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-audit-immut-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired AuditLog audit;

    @BeforeEach
    void oneEntry() {
        if (jdbc.queryForObject("SELECT count(*) FROM security_audit_log", Long.class) == 0) {
            tx.executeWithoutResult(s -> audit.append("TEST_EVENT", "tester", Map.of("n", 1)));
        }
    }

    @Test
    void updateFails() {
        assertThatThrownBy(() -> jdbc.update("UPDATE security_audit_log SET actor_id = 'mallory'"))
                .isInstanceOf(DataAccessException.class).hasMessageContaining(MESSAGE);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM security_audit_log WHERE actor_id = 'mallory'", Long.class))
                .isZero();
    }

    @Test
    void deleteFails() {
        long before = jdbc.queryForObject("SELECT count(*) FROM security_audit_log", Long.class);
        assertThatThrownBy(() -> jdbc.update("DELETE FROM security_audit_log"))
                .isInstanceOf(DataAccessException.class).hasMessageContaining(MESSAGE);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM security_audit_log", Long.class)).isEqualTo(before);
    }

    @Test
    void truncateFails() {
        assertThatThrownBy(() -> jdbc.execute("TRUNCATE security_audit_log"))
                .isInstanceOf(DataAccessException.class).hasMessageContaining(MESSAGE);
        assertThat(audit.verify().valid()).isTrue();
    }

    @Test
    void appendStillWorks() {
        long before = jdbc.queryForObject("SELECT count(*) FROM security_audit_log", Long.class);
        tx.executeWithoutResult(s -> audit.append("TEST_EVENT", "tester", Map.of("n", 2)));
        assertThat(jdbc.queryForObject("SELECT count(*) FROM security_audit_log", Long.class)).isEqualTo(before + 1);
        assertThat(audit.verify().valid()).isTrue();
    }

    /** Java string literals and text blocks, and SQL statements in migrations, under server/src/main. */
    static List<String> sqlStrings(Path file) throws IOException {
        String src = Files.readString(file);
        List<String> out = new ArrayList<>();
        if (file.toString().endsWith(".java")) {
            Matcher blocks = Pattern.compile("\"\"\"(.*?)\"\"\"", Pattern.DOTALL).matcher(src);
            while (blocks.find()) {
                out.add(blocks.group(1));
            }
            String noBlocks = blocks.replaceAll("");
            Matcher lits = Pattern.compile("\"((?:[^\"\\\\\\n]|\\\\.)*)\"").matcher(noBlocks);
            while (lits.find()) {
                out.add(lits.group(1));
            }
        } else {
            String noComments = src.replaceAll("--[^\\n]*", "");
            // Statements, keeping $$ ... $$ function bodies whole.
            for (String stmt : noComments.split(";(?=(?:[^$]*\\$\\$[^$]*\\$\\$)*[^$]*$)")) {
                out.add(stmt);
            }
        }
        return out;
    }

    static boolean editsAuditLog(String sql, boolean migration) {
        String s = sql.replaceAll("\\s+", " ").trim();
        if (!s.contains("security_audit_log")) {
            return false;
        }
        if (migration) {
            // A migration statement that itself modifies the table (the trigger DDL names UPDATE/DELETE as events).
            return Pattern.compile("(?i)^(UPDATE\\s+security_audit_log|DELETE\\s+FROM\\s+security_audit_log|TRUNCATE\\b.*security_audit_log)")
                    .matcher(s).find();
        }
        return Pattern.compile("(?i)\\b(UPDATE|DELETE|TRUNCATE)\\b").matcher(s).find();
    }

    @Test
    void noMainSourceEditsTheAuditLog() throws IOException {
        Path root = Path.of(System.getProperty("user.dir")).resolve("src/main");
        if (!Files.isDirectory(root)) {
            root = Path.of(System.getProperty("user.dir")).resolve("server/src/main");
        }
        List<String> offenders = new ArrayList<>();
        int scanned = 0;
        try (Stream<Path> files = Files.walk(root)) {
            for (Path f : files.filter(p -> p.toString().endsWith(".java") || p.toString().endsWith(".sql")).toList()) {
                scanned++;
                boolean migration = f.toString().endsWith(".sql");
                for (String sql : sqlStrings(f)) {
                    if (editsAuditLog(sql, migration)) {
                        offenders.add(root.relativize(f) + ": " + sql.replaceAll("\\s+", " ").trim());
                    }
                }
            }
        }
        assertThat(scanned).isGreaterThan(50);
        assertThat(offenders).isEmpty();
        // The checker itself catches the forms it is meant to catch.
        assertThat(editsAuditLog("UPDATE security_audit_log SET actor_id = ?", false)).isTrue();
        assertThat(editsAuditLog("DELETE FROM security_audit_log WHERE sequence_id = ?", false)).isTrue();
        assertThat(editsAuditLog("INSERT INTO security_audit_log (event_type) VALUES (?)", false)).isFalse();
        assertThat(editsAuditLog("DELETE FROM security_audit_log", true)).isTrue();
        assertThat(editsAuditLog("CREATE TRIGGER t BEFORE UPDATE OR DELETE ON security_audit_log FOR EACH ROW", true))
                .isFalse();
    }
}
