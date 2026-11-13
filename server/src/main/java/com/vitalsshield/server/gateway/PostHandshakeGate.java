package com.vitalsshield.server.gateway;

import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import com.vitalsshield.server.session.ActiveSessionRegistry;
import io.netty.channel.Channel;
import io.netty.handler.ssl.SslHandler;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Runs when an mTLS handshake completes, including resumed handshakes where the trust manager is not called. Reads
 * the peer leaf from the SSLSession, registers the channel, then checks the deny-list (in that order, so a revoke
 * racing this gate is always caught by one side). In-memory only: it runs on the event loop.
 */
@Component
public class PostHandshakeGate {

    private static final Logger log = LoggerFactory.getLogger(PostHandshakeGate.class);

    private final CertificateDenyList denyList;
    private final ActiveSessionRegistry sessions;
    private final AtomicLong postHandshakeRejects = new AtomicLong();

    public PostHandshakeGate(CertificateDenyList denyList, ActiveSessionRegistry sessions) {
        this.denyList = denyList;
        this.sessions = sessions;
    }

    /** Called once per accepted channel, after Reactor Netty has installed its SslHandler. */
    public void attach(Channel channel) {
        SslHandler ssl = channel.pipeline().get(SslHandler.class);
        if (ssl == null) {
            log.warn("mTLS connection without SslHandler; closing");
            channel.close();
            return;
        }
        ssl.handshakeFuture().addListener(f -> {
            if (!f.isSuccess()) {
                return;
            }
            CertKey key;
            try {
                Certificate[] peer = ssl.engine().getSession().getPeerCertificates();
                key = CertKey.from((X509Certificate) peer[0]);
            } catch (Exception e) {
                log.info("mTLS session without a usable peer certificate; closing: {}", e.toString());
                postHandshakeRejects.incrementAndGet();
                channel.close();
                return;
            }
            sessions.register(key, channel);
            if (denyList.isDenied(key)) {
                postHandshakeRejects.incrementAndGet();
                log.info("Post-handshake gate closed deny-listed session (serial={}, issuer_key_hash={})",
                        key.serial(), key.issuerKeyHash());
                channel.close();
            }
        });
    }

    public long postHandshakeRejects() {
        return postHandshakeRejects.get();
    }
}
