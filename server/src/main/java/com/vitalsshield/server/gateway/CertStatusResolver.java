package com.vitalsshield.server.gateway;

import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.SslInfo;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Authoritative per-request certificate status on the mTLS port. Deliberately uncached: a revoke is visible to the
 * very next request. The DB read runs on boundedElastic.
 */
@Component
public class CertStatusResolver implements WebFilter, Ordered {

    public static final int ORDER = PortEnforcementWebFilter.ORDER + 10;

    private final ListenerProperties listeners;
    private final CertificateDenyList denyList;
    private final JdbcTemplate jdbc;
    private final Clock clock;

    public CertStatusResolver(ListenerProperties listeners, CertificateDenyList denyList, JdbcTemplate jdbc,
                              Clock clock) {
        this.listeners = listeners;
        this.denyList = denyList;
        this.jdbc = jdbc;
        this.clock = clock;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    record Row(String status, String deviceId, Instant notBefore, Instant notAfter, Instant graceExpiresAt,
               String thumbprint) {
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        InetSocketAddress local = exchange.getRequest().getLocalAddress();
        if (local == null || local.getPort() != listeners.mtlsPort()) {
            return chain.filter(exchange);
        }
        SslInfo ssl = exchange.getRequest().getSslInfo();
        X509Certificate[] peer = ssl == null ? null : ssl.getPeerCertificates();
        if (peer == null || peer.length == 0) {
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }
        CertKey key;
        try {
            key = CertKey.from(peer[0]);
        } catch (RuntimeException e) {
            return reject(exchange, "UNKNOWN");
        }
        Instant now = clock.instant();
        var denied = denyList.entry(key).filter(e -> !now.isBefore(e.deniedFrom()));
        if (denied.isPresent()) {
            return reject(exchange, denied.get().reason());
        }

        CertKey k = key;
        return Mono.fromCallable(() -> load(k))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(rows -> {
                    String verdict = verdict(rows, now);
                    if (verdict != null) {
                        return reject(exchange, verdict);
                    }
                    Row row = rows.get(0);
                    exchange.getAttributes().put(ResolvedCert.ATTRIBUTE,
                            new ResolvedCert(k.issuerKeyHash(), k.serial(), row.deviceId(), row.status(),
                                    row.thumbprint()));
                    return chain.filter(exchange);
                });
    }

    /** Null means accept. */
    static String verdict(List<Row> rows, Instant now) {
        if (rows.isEmpty()) {
            return "UNKNOWN";
        }
        Row r = rows.get(0);
        switch (r.status()) {
            case "REVOKED":
                return "REVOKED";
            case "EXPIRED":
                return "EXPIRED";
            case "RENEWED":
                if (r.graceExpiresAt() == null || !now.isBefore(r.graceExpiresAt())) {
                    return "SUPERSEDED";
                }
                break;
            case "ACTIVE":
            case "ISSUED_PENDING_USE":
                break;
            default:
                return "UNKNOWN";
        }
        if (now.isBefore(r.notBefore()) || !now.isBefore(r.notAfter())) {
            return "OUTSIDE_VALIDITY";
        }
        return null;
    }

    private List<Row> load(CertKey key) {
        return jdbc.query("""
                SELECT status::text AS status, device_id, not_before, not_after, grace_expires_at, cert_thumbprint_s256
                  FROM certificates
                 WHERE issuer_key_hash = ? AND serial_number = ?
                """, (rs, i) -> new Row(rs.getString("status"), rs.getString("device_id"),
                rs.getTimestamp("not_before").toInstant(), rs.getTimestamp("not_after").toInstant(),
                instant(rs.getTimestamp("grace_expires_at")), rs.getString("cert_thumbprint_s256")),
                key.issuerKeyHash(), key.serial());
    }

    private static Instant instant(Timestamp ts) {
        return ts == null ? null : ts.toInstant();
    }

    private static Mono<Void> reject(ServerWebExchange exchange, String reason) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] body = ("{\"error\":\"CERT_NOT_ACCEPTED\",\"reason\":\"" + reason + "\"}")
                .getBytes(StandardCharsets.US_ASCII);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }
}
