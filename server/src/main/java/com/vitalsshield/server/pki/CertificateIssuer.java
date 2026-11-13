package com.vitalsshield.server.pki;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Issues leaf certificates. Stand-in boundary for Keytos EZCA: the KMS-backed implementation can be swapped for an
 * EZCA client. No persistence here; enrollment persists the result in a later phase.
 *
 * <p>The blocking methods may make network calls (KMS, DB). From reactive code use the {@code Async} variants, which
 * run on {@code boundedElastic}.
 */
public interface CertificateIssuer {

    X509Certificate issueDeviceLeaf(String deviceId, SubjectPublicKeyInfo spki, Duration ttl);

    X509Certificate issueGatewayLeaf(PublicKey key, Duration ttl);

    default Mono<X509Certificate> issueDeviceLeafAsync(String deviceId, SubjectPublicKeyInfo spki, Duration ttl) {
        return Mono.fromCallable(() -> issueDeviceLeaf(deviceId, spki, ttl)).subscribeOn(Schedulers.boundedElastic());
    }

    default Mono<X509Certificate> issueGatewayLeafAsync(PublicKey key, Duration ttl) {
        return Mono.fromCallable(() -> issueGatewayLeaf(key, ttl)).subscribeOn(Schedulers.boundedElastic());
    }
}
