package com.vitalsshield.server.admin;

import com.vitalsshield.server.gateway.ListenerProperties;
import com.vitalsshield.server.gateway.PortEnforcementWebFilter;
import java.net.InetSocketAddress;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Admin port: every /api/v1/admin/** request except GET /api/v1/admin/boot-status needs
 * {@code Authorization: Bearer <setup code>} (DECISIONS #41). Missing or wrong: 401 with an empty body. Bearer mode
 * only ({@code vitalsshield.admin.auth=bearer}); in webauthn mode {@code AdminSessionWebFilter} applies.
 */
@Component
public class AdminAuthWebFilter implements WebFilter, Ordered {

    static final String PREFIX = "/api/v1/admin/";
    static final String OPEN_PATH = "/api/v1/admin/boot-status";
    static final String AUTH_STATUS_PATH = "/api/v1/admin/auth/status";

    private final ListenerProperties listeners;
    private final AdminSetupCode setupCode;

    private final AdminProperties admin;

    public AdminAuthWebFilter(ListenerProperties listeners, AdminSetupCode setupCode, AdminProperties admin) {
        this.listeners = listeners;
        this.setupCode = setupCode;
        this.admin = admin;
    }

    @Override
    public int getOrder() {
        return PortEnforcementWebFilter.ORDER + 5;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        InetSocketAddress local = exchange.getRequest().getLocalAddress();
        String path = exchange.getRequest().getPath().pathWithinApplication().value();
        if (admin.webauthn()) {
            return chain.filter(exchange); // AdminSessionWebFilter owns webauthn mode
        }
        if (local == null || local.getPort() != listeners.adminPort()
                || !(path.startsWith(PREFIX) || path.equals("/api/v1/admin"))) {
            return chain.filter(exchange);
        }
        if (HttpMethod.GET.equals(exchange.getRequest().getMethod())
                && (OPEN_PATH.equals(path) || AUTH_STATUS_PATH.equals(path))) {
            return chain.filter(exchange);
        }
        String auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (auth != null && auth.startsWith("Bearer ") && setupCode.matches(auth.substring(7).trim())) {
            return chain.filter(exchange);
        }
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}
