package com.vitalsshield.server.gateway;

import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;
import java.sql.SQLRecoverableException;
import java.sql.SQLTimeoutException;
import java.sql.SQLTransientConnectionException;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Ingest degraded mode (spec Section 4, DECISIONS #103): when the database cannot be reached or times out on the
 * telemetry path, the answer is 503 STORE_UNAVAILABLE with a jittered Retry-After of 3 to 8 s. A batch whose
 * statement did not commit is never answered 200; the device resends the same frame, and if the statement had in fact
 * committed, the retry is answered as an idempotent retry.
 *
 * <p>Only connection and timeout failures match. Any other database error (a constraint, a bug) stays a 500.
 */
public final class StoreUnavailable {

    public static final String ERROR = "STORE_UNAVAILABLE";
    public static final Map<String, Object> BODY = Map.of("error", ERROR);

    private StoreUnavailable() {
    }

    /** A random integer from 3 to 8, so retries from many devices spread out. */
    public static int retryAfterSeconds() {
        return ThreadLocalRandom.current().nextInt(3, 9);
    }

    /** True when {@code t}, or any cause, is a connection or timeout failure of the database. */
    public static boolean matches(Throwable t) {
        int depth = 0;
        for (Throwable c = t; c != null && depth < 16; c = c.getCause(), depth++) {
            if (c instanceof DataAccessResourceFailureException       // includes CannotGetJdbcConnectionException
                    || c instanceof TransientDataAccessResourceException
                    || c instanceof QueryTimeoutException
                    || c instanceof SQLTransientConnectionException   // HikariCP: connection not available
                    || c instanceof SQLNonTransientConnectionException
                    || c instanceof SQLRecoverableException
                    || c instanceof SQLTimeoutException) {
                return true;
            }
            if (c instanceof SQLException s && s.getSQLState() != null) {
                String state = s.getSQLState();
                // 08xxx connection exception; 57P01-57P03 server shutting down or not accepting connections;
                // 57014 statement canceled (statement_timeout); 53300 too many connections.
                if (state.startsWith("08") || state.startsWith("57P") || state.equals("57014")
                        || state.equals("53300")) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Writes the 503 directly, for a WebFilter. */
    public static Mono<Void> write(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
        response.getHeaders().set(HttpHeaders.RETRY_AFTER, String.valueOf(retryAfterSeconds()));
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] body = ("{\"error\":\"" + ERROR + "\"}").getBytes(StandardCharsets.US_ASCII);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }
}
