package com.vitalsshield.simulator;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

/**
 * HTTPS to the gateway with java.net.http.HttpClient. Trusts only the Root CA loaded from the trust file on every
 * launch (never pinned in code). Hostname verification stays on; the default URLs use 127.0.0.1, which the gateway
 * leaf carries as an IP SAN (DECISIONS #36).
 */
public final class GatewayClient {

    public record Response(int status, String body, java.net.http.HttpHeaders headers) {
    }

    private final HttpClient http;

    private GatewayClient(HttpClient http) {
        this.http = http;
    }

    /** Public port client: no client certificate. */
    public static GatewayClient publicClient(Path trustFile) {
        return new GatewayClient(build(sslContext(trustFile, null, null)));
    }

    /** mTLS port client: presents the OLK key and certificate. */
    public static GatewayClient mtlsClient(Path trustFile, PrivateKey olkKey, X509Certificate olkCert) {
        return new GatewayClient(build(sslContext(trustFile, olkKey, olkCert)));
    }

    public Response get(URI uri) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(15)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        return new Response(r.statusCode(), r.body(), r.headers());
    }

    public Response postJson(URI uri, String json) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8)).build(),
                HttpResponse.BodyHandlers.ofString());
        return new Response(r.statusCode(), r.body(), r.headers());
    }

    /** POST a compact JWS (Content-Type application/jose) over this client's persistent connection. */
    public Response postJose(URI uri, String compactJws) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(15))
                        .header("Content-Type", "application/jose")
                        .POST(HttpRequest.BodyPublishers.ofString(compactJws, StandardCharsets.US_ASCII)).build(),
                HttpResponse.BodyHandlers.ofString());
        return new Response(r.statusCode(), r.body(), r.headers());
    }

    /** True if {@code e} (or a cause) is a TLS-level refusal: a handshake failure or a fatal alert from the server. */
    public static boolean isHandshakeRefused(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof javax.net.ssl.SSLHandshakeException) {
                return true;
            }
            if (t instanceof javax.net.ssl.SSLException && t.getMessage() != null
                    && t.getMessage().toLowerCase(java.util.Locale.ROOT).contains("alert")) {
                return true;
            }
        }
        return false;
    }

    private static HttpClient build(SSLContext ctx) {
        SSLParameters params = new SSLParameters();
        params.setProtocols(new String[] {"TLSv1.3"});
        return HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .sslContext(ctx)
                .sslParameters(params)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    static SSLContext sslContext(Path trustFile, PrivateKey key, X509Certificate cert) {
        try {
            X509Certificate root = SimulatorStateStore.parseCert(Files.readString(trustFile, StandardCharsets.US_ASCII));
            KeyStore ts = KeyStore.getInstance("PKCS12");
            ts.load(null, null);
            ts.setCertificateEntry("root", root);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);

            KeyManagerFactory kmf = null;
            if (key != null) {
                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(null, null);
                ks.setKeyEntry("olk", key, new char[0], new X509Certificate[] {cert});
                kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(ks, new char[0]);
            }
            SSLContext ctx = SSLContext.getInstance("TLSv1.3");
            ctx.init(kmf == null ? null : kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return ctx;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("cannot build TLS context from trust file " + trustFile, e);
        }
    }
}
