package com.vitalsshield.server.gateway;

import com.vitalsshield.server.pki.GatewayTlsMaterial;
import com.vitalsshield.server.pki.trust.DynamicMtlsTrustManager;
import io.netty.handler.ssl.ClientAuth;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.context.ApplicationContext;
import org.springframework.http.server.reactive.HttpHandler;
import org.springframework.http.server.reactive.ReactorHttpHandlerAdapter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;
import reactor.netty.DisposableServer;
import reactor.netty.http.Http11SslContextSpec;
import reactor.netty.http.HttpProtocol;
import reactor.netty.http.server.HttpServer;

/**
 * Binds the three listeners. Only {@link com.vitalsshield.server.boot.BootSequence} calls {@link #bindAll()}, as its
 * last step. All three share one HttpHandler; PortEnforcementWebFilter decides which paths each port serves.
 *
 * <ul>
 *   <li>mTLS (8443): TLS 1.3 only, JDK provider, client cert REQUIRED, DynamicMtlsTrustManager, post-handshake gate</li>
 *   <li>public (8444): TLS 1.3 only, JDK provider, no client cert</li>
 *   <li>admin (8445): plain HTTP, always 127.0.0.1</li>
 * </ul>
 */
@Component
public class ListenerManager implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(ListenerManager.class);

    /** JDK SSLSessionContext treats 0 as "no limit" for both, so 1 is the smallest real setting. */
    static final long SESSION_CACHE_SIZE = 1;
    static final long SESSION_TIMEOUT_SECONDS = 1;

    private final ApplicationContext context;
    private final ListenerProperties props;
    private final GatewayTlsMaterial tls;
    private final DynamicMtlsTrustManager trustManager;
    private final PostHandshakeGate gate;
    private final Map<String, DisposableServer> servers = new LinkedHashMap<>();

    public ListenerManager(ApplicationContext context, ListenerProperties props, GatewayTlsMaterial tls,
                           DynamicMtlsTrustManager trustManager, PostHandshakeGate gate) {
        this.context = context;
        this.props = props;
        this.tls = tls;
        this.trustManager = trustManager;
        this.gate = gate;
    }

    /** Binds (or re-binds, after a rebuild issued new gateway TLS material) all three listeners. */
    public synchronized void bindAll() {
        disposeAll();
        HttpHandler handler = WebHttpHandlerBuilder.applicationContext(context).build();
        ReactorHttpHandlerAdapter adapter = new ReactorHttpHandlerAdapter(handler);

        servers.put("mtls", HttpServer.create()
                .protocol(HttpProtocol.HTTP11)
                .host(props.bindHost())
                .port(props.mtlsPort())
                .secure(spec -> spec.sslContext(sslSpec(ClientAuth.REQUIRE)))
                // Once per TCP connection. (doOnConnection fires per HTTP request on a keep-alive connection.)
                .doOnChannelInit((observer, channel, remote) -> gate.attach(channel))
                .handle(adapter)
                .bindNow());
        servers.put("public", HttpServer.create()
                .protocol(HttpProtocol.HTTP11)
                .host(props.bindHost())
                .port(props.publicPort())
                .secure(spec -> spec.sslContext(sslSpec(ClientAuth.NONE)))
                .handle(adapter)
                .bindNow());
        servers.put("admin", HttpServer.create()
                .protocol(HttpProtocol.HTTP11)
                .host(ListenerProperties.ADMIN_BIND_HOST)
                .port(props.adminPort())
                .handle(adapter)
                .bindNow());
        servers.forEach((name, s) -> log.info("Listener {} bound on {}", name, s.address()));
    }

    public synchronized List<InetSocketAddress> boundAddresses() {
        List<InetSocketAddress> out = new ArrayList<>();
        servers.values().forEach(s -> out.add((InetSocketAddress) s.address()));
        return out;
    }

    public synchronized Map<String, InetSocketAddress> boundByName() {
        Map<String, InetSocketAddress> out = new LinkedHashMap<>();
        servers.forEach((name, s) -> out.put(name, (InetSocketAddress) s.address()));
        return out;
    }

    @Override
    public void destroy() {
        disposeAll();
    }

    private synchronized void disposeAll() {
        servers.forEach((name, s) -> {
            s.disposeNow();
            log.info("Listener {} disposed", name);
        });
        servers.clear();
    }

    private Http11SslContextSpec sslSpec(ClientAuth clientAuth) {
        List<X509Certificate> chain = tls.certificateChain();
        return Http11SslContextSpec.forServer(tls.privateKey(), chain.toArray(X509Certificate[]::new))
                .configure(b -> {
                    b.sslProvider(io.netty.handler.ssl.SslProvider.JDK)
                            .protocols("TLSv1.3")
                            .clientAuth(clientAuth)
                            .sessionCacheSize(SESSION_CACHE_SIZE)
                            .sessionTimeout(SESSION_TIMEOUT_SECONDS);
                    if (clientAuth == ClientAuth.REQUIRE) {
                        b.trustManager(trustManager);
                    }
                });
    }
}
