package com.vitalsshield.server.db;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Starts the full server application context and proves Flyway actually ran. In Boot 4 Flyway autoconfiguration
 * lives in spring-boot-flyway (pulled in by spring-boot-starter-flyway); without it the context still starts but no
 * migration runs, and this test fails because flyway_schema_history does not exist.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class SpringContextFlywayIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    @Autowired
    JdbcTemplate jdbc;

    @Test
    void flywayAppliedBaselineOnStartup() {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT version, success FROM flyway_schema_history WHERE version = '1'");

        assertThat(rows).singleElement().satisfies(row -> {
            assertThat(row.get("version")).isEqualTo("1");
            assertThat(row.get("success")).isEqualTo(true);
        });
    }
}
