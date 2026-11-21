package com.vitalsshield.server.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.SQLException;
import java.sql.SQLTransientConnectionException;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.jdbc.UncategorizedSQLException;

/** DECISIONS #103: which database failures become 503 STORE_UNAVAILABLE and which stay 500. */
class StoreUnavailableTest {

    @Test
    void connectionAndTimeoutFailuresMatch() {
        assertThat(StoreUnavailable.matches(new CannotGetJdbcConnectionException("pool",
                new SQLTransientConnectionException("HikariPool-1 - Connection is not available")))).isTrue();
        assertThat(StoreUnavailable.matches(new SQLTransientConnectionException("timeout"))).isTrue();
        assertThat(StoreUnavailable.matches(new QueryTimeoutException("slow"))).isTrue();
        assertThat(StoreUnavailable.matches(new UncategorizedSQLException("ingest", "WITH ...",
                new SQLException("An I/O error occurred while sending to the backend.", "08006")))).isTrue();
        assertThat(StoreUnavailable.matches(new RuntimeException(
                new SQLException("terminating connection due to administrator command", "57P01")))).isTrue();
        assertThat(StoreUnavailable.matches(new SQLException("canceling statement due to statement timeout",
                "57014"))).isTrue();
    }

    @Test
    void otherDatabaseErrorsDoNotMatch() {
        assertThat(StoreUnavailable.matches(new DataIntegrityViolationException("duplicate key",
                new SQLException("duplicate key value", "23505")))).isFalse();
        assertThat(StoreUnavailable.matches(new SQLException("syntax error", "42601"))).isFalse();
        assertThat(StoreUnavailable.matches(new IllegalStateException("bug"))).isFalse();
    }

    @Test
    void retryAfterIsThreeToEightSeconds() {
        for (int i = 0; i < 1000; i++) {
            assertThat(StoreUnavailable.retryAfterSeconds()).isBetween(3, 8);
        }
    }
}
