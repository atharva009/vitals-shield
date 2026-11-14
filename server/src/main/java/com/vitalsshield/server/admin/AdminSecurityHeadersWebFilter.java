package com.vitalsshield.server.admin;

import com.vitalsshield.server.gateway.ListenerProperties;
import com.vitalsshield.server.gateway.PortEnforcementWebFilter;
import java.net.InetSocketAddress;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Security headers on every admin-port response (dashboard and admin API). HTML responses from the dashboard handler
 * replace the CSP with one that also lists the SHA-256 of each inline script (DECISIONS #52).
 */
@Component
public class AdminSecurityHeadersWebFilter implements WebFilter, Ordered {

    public static final String CSP = "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
            + "style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
            + "form-action 'self'";

    private final ListenerProperties listeners;

    public AdminSecurityHeadersWebFilter(ListenerProperties listeners) {
        this.listeners = listeners;
    }

    @Override
    public int getOrder() {
        return PortEnforcementWebFilter.ORDER + 1;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        InetSocketAddress local = exchange.getRequest().getLocalAddress();
        if (local != null && local.getPort() == listeners.adminPort()) {
            ServerHttpResponse r = exchange.getResponse();
            HttpHeaders h = r.getHeaders();
            h.set("X-Content-Type-Options", "nosniff");
            h.set("X-Frame-Options", "DENY");
            h.set("Referrer-Policy", "no-referrer");
            h.set("Content-Security-Policy", CSP);
            if (exchange.getRequest().getPath().value().startsWith("/api/")) {
                h.set(HttpHeaders.CACHE_CONTROL, "no-store");
            }
        }
        return chain.filter(exchange);
    }
}
