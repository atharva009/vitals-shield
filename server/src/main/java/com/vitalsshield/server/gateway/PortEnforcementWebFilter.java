package com.vitalsshield.server.gateway;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.PathContainer;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

/**
 * Runs first. Each listener port serves a fixed set of paths; anything else is 404 with an empty body (never 403,
 * which would confirm the route exists on another port). An unknown local port serves nothing.
 */
@Component
public class PortEnforcementWebFilter implements WebFilter, Ordered {

    public static final int ORDER = Ordered.HIGHEST_PRECEDENCE;

    private final Map<Integer, List<PathPattern>> allowed;

    public PortEnforcementWebFilter(ListenerProperties props) {
        this.allowed = Map.of(
                props.mtlsPort(), patterns(
                        "/api/v1/telemetry/**", "/api/v1/devices/renew", "/api/v1/devices/renew-challenge"),
                props.publicPort(), patterns(
                        "/api/v1/devices/enroll", "/api/v1/devices/challenge", "/api/v1/devices/re-enroll",
                        "/api/v1/pki/**"),
                props.adminPort(), patterns(
                        "/api/v1/admin/**", "/"));
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        InetSocketAddress local = exchange.getRequest().getLocalAddress();
        List<PathPattern> patterns = local == null ? List.of() : allowed.getOrDefault(local.getPort(), List.of());
        PathContainer path = exchange.getRequest().getPath().pathWithinApplication();
        for (PathPattern p : patterns) {
            if (p.matches(path)) {
                return chain.filter(exchange);
            }
        }
        exchange.getResponse().setStatusCode(HttpStatus.NOT_FOUND);
        return exchange.getResponse().setComplete();
    }

    private static List<PathPattern> patterns(String... raw) {
        return java.util.Arrays.stream(raw).map(PathPatternParser.defaultInstance::parse).toList();
    }
}
