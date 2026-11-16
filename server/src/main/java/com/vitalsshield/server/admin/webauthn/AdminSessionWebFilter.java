package com.vitalsshield.server.admin.webauthn;

import com.vitalsshield.server.admin.AdminProperties;
import com.vitalsshield.server.gateway.ListenerProperties;
import com.vitalsshield.server.gateway.PortEnforcementWebFilter;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Set;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Admin port, webauthn mode (DECISIONS #55, #59, #60):
 * <ol>
 *   <li>a GET/HEAD for a dashboard page addressed to 127.0.0.1 or ::1 is redirected (307) to http://localhost:port,
 *       because the passkey RP id is "localhost";</li>
 *   <li>every non-GET admin API request must carry an Origin header equal to an allowed origin (403 otherwise);</li>
 *   <li>the session cookie authenticates; outside the open sign-in paths a missing or expired session is 401.</li>
 * </ol>
 * The setup-code bearer is not accepted here; only register/begin looks at it, for the first passkey.
 */
@Component
public class AdminSessionWebFilter implements WebFilter, Ordered {

    public static final String SESSION_ATTR = "vitalsshield.adminSession";
    static final String API = "/api/v1/admin";
    private static final Set<String> OPEN_GET = Set.of(API + "/boot-status", API + "/auth/status");
    private static final Set<String> OPEN_POST = Set.of(API + "/session/begin", API + "/session/finish",
            API + "/session/logout", API + "/passkeys/register/begin", API + "/passkeys/register/finish");
    /** Phase 4/5 single-step quarantine: does not exist in webauthn mode (DECISIONS #58), 404 for every caller. */
    private static final java.util.regex.Pattern RETIRED = java.util.regex.Pattern.compile(
            "/api/v1/admin/devices/[^/]+/quarantine");
    private static final Set<String> IP_HOSTS = Set.of("127.0.0.1", "::1", "[::1]", "0:0:0:0:0:0:0:1");

    private final ListenerProperties listeners;
    private final AdminProperties admin;
    private final AdminSessionStore sessions;
    private final WebAuthnOrigins origins;

    public AdminSessionWebFilter(ListenerProperties listeners, AdminProperties admin, AdminSessionStore sessions,
                                 WebAuthnOrigins origins) {
        this.listeners = listeners;
        this.admin = admin;
        this.sessions = sessions;
        this.origins = origins;
    }

    @Override
    public int getOrder() {
        return PortEnforcementWebFilter.ORDER + 4;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest req = exchange.getRequest();
        InetSocketAddress local = req.getLocalAddress();
        if (!admin.webauthn() || local == null || local.getPort() != listeners.adminPort()) {
            return chain.filter(exchange);
        }
        String path = req.getPath().pathWithinApplication().value();
        HttpMethod method = req.getMethod();
        boolean read = HttpMethod.GET.equals(method) || HttpMethod.HEAD.equals(method);

        if (!path.startsWith("/api/")) {
            InetSocketAddress host = req.getHeaders().getHost();
            if (read && host != null && IP_HOSTS.contains(host.getHostString())) {
                String query = req.getURI().getRawQuery();
                exchange.getResponse().setStatusCode(HttpStatus.TEMPORARY_REDIRECT);
                exchange.getResponse().getHeaders().setLocation(URI.create("http://" + WebAuthnOrigins.RP_ID + ":"
                        + listeners.adminPort() + req.getURI().getRawPath() + (query == null ? "" : "?" + query)));
                return exchange.getResponse().setComplete();
            }
            return chain.filter(exchange);
        }
        if (!(path.equals(API) || path.startsWith(API + "/"))) {
            return chain.filter(exchange);
        }
        if (RETIRED.matcher(path).matches()) {
            exchange.getResponse().setStatusCode(HttpStatus.NOT_FOUND);
            return exchange.getResponse().setComplete();
        }
        if (!read) {
            String origin = req.getHeaders().getOrigin();
            if (origin == null || !origins.origins().contains(origin)) {
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }
        }
        HttpCookie cookie = req.getCookies().getFirst(AdminSessionStore.COOKIE);
        sessions.get(cookie == null ? null : cookie.getValue())
                .ifPresent(s -> exchange.getAttributes().put(SESSION_ATTR, s));
        boolean open = read ? OPEN_GET.contains(path) : OPEN_POST.contains(path);
        if (open || exchange.getAttributes().containsKey(SESSION_ATTR)) {
            return chain.filter(exchange);
        }
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    /** Bearer token from the Authorization header, or null. */
    static String bearer(ServerHttpRequest req) {
        String auth = req.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        return auth != null && auth.startsWith("Bearer ") ? auth.substring(7).trim() : null;
    }
}
