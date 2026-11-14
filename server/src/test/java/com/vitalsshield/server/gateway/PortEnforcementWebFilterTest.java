package com.vitalsshield.server.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

class PortEnforcementWebFilterTest {

    static final int MTLS = 8443;
    static final int PUBLIC = 8444;
    static final int ADMIN = 8445;

    final PortEnforcementWebFilter filter =
            new PortEnforcementWebFilter(new ListenerProperties("127.0.0.1", MTLS, PUBLIC, ADMIN));

    static List<Arguments> routes() {
        return List.of(
                Arguments.of("/api/v1/telemetry/ping", MTLS),
                Arguments.of("/api/v1/telemetry/ingest", MTLS),
                Arguments.of("/api/v1/devices/renew", MTLS),
                Arguments.of("/api/v1/devices/renew-challenge", MTLS),
                Arguments.of("/api/v1/devices/enroll", PUBLIC),
                Arguments.of("/api/v1/devices/challenge", PUBLIC),
                Arguments.of("/api/v1/devices/re-enroll", PUBLIC),
                Arguments.of("/api/v1/pki/intermediate-crl.pem", PUBLIC),
                Arguments.of("/api/v1/pki/root-crl.pem", PUBLIC),
                Arguments.of("/api/v1/admin/boot-status", ADMIN),
                Arguments.of("/api/v1/admin", ADMIN),
                Arguments.of("/api/v1/pki", PUBLIC));
    }

    @ParameterizedTest
    @MethodSource("routes")
    void routePassesOnlyOnItsOwnPort(String path, int allowedPort) {
        for (int port : new int[] {MTLS, PUBLIC, ADMIN, 9999}) {
            Outcome outcome = run(path, port);
            if (port == allowedPort) {
                assertThat(outcome.passed()).as("%s on %d", path, port).isTrue();
            } else {
                assertThat(outcome.passed()).as("%s on %d", path, port).isFalse();
                assertThat(outcome.status()).isEqualTo(HttpStatus.NOT_FOUND);
                assertThat(outcome.bodyEmpty()).isTrue();
            }
        }
    }

    @ParameterizedTest
    @MethodSource("unlistedPaths")
    void unlistedApiPathIs404OnEveryPort(String path) {
        for (int port : new int[] {MTLS, PUBLIC, ADMIN}) {
            Outcome outcome = run(path, port);
            assertThat(outcome.passed()).as("%s on %d", path, port).isFalse();
            assertThat(outcome.status()).isEqualTo(HttpStatus.NOT_FOUND);
        }
    }

    static List<String> unlistedPaths() {
        // Note: "/api/v1/admin" and "/api/v1/pki" (no trailing segment) match their "/**" patterns and pass on
        // their own port only; see routes().
        return List.of("/api/v1/devices/renewal", "/api/v1/devices", "/api/v1/telemetryx", "/api/v2/admin/x",
                "/api/v1/adminx");
    }

    /** Dashboard static paths (DECISIONS #47): passed on the admin port only, 404 on 8443 and 8444. */
    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"/", "/index.html", "/_next/static/chunks/x.js",
            "/favicon.ico", "/actuator", "/admin"})
    void dashboardPathsOnlyOnAdminPort(String path) {
        assertThat(run(path, ADMIN).passed()).as("%s on admin", path).isTrue();
        for (int port : new int[] {MTLS, PUBLIC}) {
            Outcome o = run(path, port);
            assertThat(o.passed()).as("%s on %d", path, port).isFalse();
            assertThat(o.status()).isEqualTo(HttpStatus.NOT_FOUND);
        }
    }

    record Outcome(boolean passed, HttpStatus status, boolean bodyEmpty) {
    }

    private Outcome run(String path, int localPort) {
        MockServerHttpRequest request = MockServerHttpRequest.get(path)
                .localAddress(new InetSocketAddress("127.0.0.1", localPort))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        AtomicBoolean passed = new AtomicBoolean();
        WebFilterChain chain = ex -> {
            passed.set(true);
            return Mono.empty();
        };
        filter.filter(exchange, chain).block();
        HttpStatus status = exchange.getResponse().getStatusCode() == null
                ? null : HttpStatus.valueOf(exchange.getResponse().getStatusCode().value());
        boolean empty = passed.get()
                || exchange.getResponse().getBodyAsString().blockOptional().orElse("").isEmpty();
        return new Outcome(passed.get(), status, empty);
    }
}
