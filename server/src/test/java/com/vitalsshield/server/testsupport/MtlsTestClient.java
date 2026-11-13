package com.vitalsshield.server.testsupport;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * Minimal TLS + HTTP/1.1 client for listener tests. A fresh SSLContext per connection, so there is no client-side
 * session reuse. Trusts only the given Root, verifies the server name "localhost", optionally presents a client key
 * and chain, and keeps the connection open between requests (keep-alive).
 *
 * <p>TLS 1.3 detail: the client finishes its side of the handshake before the server has checked the client
 * certificate, so a server-side rejection shows up as an alert on the first read, not in startHandshake().
 */
public final class MtlsTestClient {

    private MtlsTestClient() {
    }

    public record Response(int status, String body) {
    }

    /** What happened when we tried to connect and send one request. */
    public enum Kind { HTTP, TLS_REJECTED, CLOSED_WITHOUT_RESPONSE, CONNECT_REFUSED }

    public record Attempt(Kind kind, Response response, String detail) {
        public boolean is200() {
            return kind == Kind.HTTP && response.status() == 200;
        }
    }

    public static Connection connect(int port, X509Certificate trustedRoot, PrivateKey key,
                                     List<X509Certificate> chain, String... protocols) throws IOException {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            KeyManagerFactory kmf = null;
            if (key != null) {
                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(null, null);
                ks.setKeyEntry("client", key, "pw".toCharArray(), chain.toArray(X509Certificate[]::new));
                kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(ks, "pw".toCharArray());
            }
            KeyStore ts = KeyStore.getInstance("PKCS12");
            ts.load(null, null);
            ts.setCertificateEntry("root", trustedRoot);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);
            ctx.init(kmf == null ? null : kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            Socket plain = new Socket();
            plain.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 2000);
            SSLSocket ssl = (SSLSocket) ctx.getSocketFactory().createSocket(plain, "localhost", port, true);
            SSLParameters params = ssl.getSSLParameters();
            params.setEndpointIdentificationAlgorithm("HTTPS");
            params.setServerNames(List.of(new SNIHostName("localhost")));
            params.setProtocols(protocols.length == 0 ? new String[] {"TLSv1.3"} : protocols);
            ssl.setSSLParameters(params);
            ssl.setSoTimeout(5000);
            ssl.startHandshake();
            return new Connection(ssl);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /** Connect and send one GET; classifies every failure instead of throwing. */
    public static Attempt attempt(int port, X509Certificate trustedRoot, PrivateKey key, List<X509Certificate> chain,
                                  String path, String... protocols) {
        Connection c;
        try {
            c = connect(port, trustedRoot, key, chain, protocols);
        } catch (java.net.ConnectException e) {
            return new Attempt(Kind.CONNECT_REFUSED, null, e.toString());
        } catch (IOException e) {
            return new Attempt(Kind.TLS_REJECTED, null, e.toString());
        }
        try (c) {
            return new Attempt(Kind.HTTP, c.get(path), null);
        } catch (SSLException e) {
            return new Attempt(Kind.TLS_REJECTED, null, e.toString());
        } catch (IOException e) {
            return new Attempt(Kind.CLOSED_WITHOUT_RESPONSE, null, e.toString());
        }
    }

    public static final class Connection implements Closeable {
        private final SSLSocket socket;
        private final InputStream in;
        private final OutputStream out;

        Connection(SSLSocket socket) throws IOException {
            this.socket = socket;
            this.in = socket.getInputStream();
            this.out = socket.getOutputStream();
        }

        public SSLSocket socket() {
            return socket;
        }

        /** GET over this (kept-alive) connection. */
        public Response get(String path) throws IOException {
            out.write(("GET " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            out.flush();
            String statusLine = readLine();
            if (statusLine == null) {
                throw new EOFException("connection closed before a response");
            }
            int status = Integer.parseInt(statusLine.split(" ")[1]);
            int contentLength = -1;
            boolean chunked = false;
            String line;
            while ((line = readLine()) != null && !line.isEmpty()) {
                String lower = line.toLowerCase(Locale.ROOT);
                if (lower.startsWith("content-length:")) {
                    contentLength = Integer.parseInt(line.substring(15).trim());
                } else if (lower.startsWith("transfer-encoding:") && lower.contains("chunked")) {
                    chunked = true;
                }
            }
            byte[] body;
            if (chunked) {
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                while (true) {
                    int size = Integer.parseInt(readLine().trim(), 16);
                    if (size == 0) {
                        readLine();
                        break;
                    }
                    buf.write(in.readNBytes(size));
                    readLine();
                }
                body = buf.toByteArray();
            } else {
                body = contentLength <= 0 ? new byte[0] : in.readNBytes(contentLength);
            }
            return new Response(status, new String(body, StandardCharsets.UTF_8));
        }

        /** True if the server closes the connection within {@code timeout} (EOF, reset, or TLS close). */
        public boolean awaitClosedWithin(Duration timeout) {
            try {
                socket.setSoTimeout((int) Math.max(1, timeout.toMillis()));
                return in.read() == -1;
            } catch (SocketTimeoutException e) {
                return false;
            } catch (IOException e) {
                return true;
            }
        }

        @Override
        public void close() {
            try {
                socket.close();
            } catch (IOException ignored) {
                // closing
            }
        }

        private String readLine() throws IOException {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            int b;
            while ((b = in.read()) != -1) {
                if (b == '\n') {
                    String s = buf.toString(StandardCharsets.US_ASCII);
                    return s.endsWith("\r") ? s.substring(0, s.length() - 1) : s;
                }
                buf.write(b);
            }
            return buf.size() == 0 ? null : buf.toString(StandardCharsets.US_ASCII);
        }
    }
}
