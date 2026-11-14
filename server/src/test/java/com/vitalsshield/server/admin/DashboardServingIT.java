package com.vitalsshield.server.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.VitalsShieldServerApplication;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.TestDevices;
import com.vitalsshield.server.testsupport.TestPorts;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** DECISIONS #47, #52: the static dashboard on the admin port only, with security headers and traversal protection. */
@Tag("integration")
@Testcontainers
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DashboardServingIT {

    @Container
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static final String INDEX = "<!DOCTYPE html><html><head><script>self.__boot=1</script>"
            + "<script src=\"/_next/static/x.js\"></script></head><body>dashboard</body></html>";

    Path dashDir;
    Path trustFile;
    ConfigurableApplicationContext ctx;
    TestPorts.Listeners ports;

    @BeforeAll
    void start() throws IOException {
        Path base = Files.createTempDirectory("vs-dash-it");
        trustFile = base.resolve("root-ca.pem");
        dashDir = base.resolve("out");
        Files.createDirectories(dashDir.resolve("_next/static"));
        Files.writeString(dashDir.resolve("index.html"), INDEX);
        Files.writeString(dashDir.resolve("_next/static/x.js"), "console.log('x');");
        Files.writeString(base.resolve("secret.txt"), "outside the dashboard dir");
        ports = TestPorts.allocate();
        ctx = startServer(dashDir, ports);
    }

    @AfterAll
    void stop() {
        ctx.close();
    }

    ConfigurableApplicationContext startServer(Path dir, TestPorts.Listeners p) {
        List<String> args = new ArrayList<>(List.of(
                "--spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "--spring.datasource.username=" + POSTGRES.getUsername(),
                "--spring.datasource.password=" + POSTGRES.getPassword(),
                "--vitalsshield.pki.trust-file=" + trustFile,
                "--vitalsshield.dashboard.dir=" + dir,
                "--spring.main.keep-alive=false"));
        args.addAll(p.asArgs());
        return new SpringApplicationBuilder(VitalsShieldServerApplication.class).profiles("local")
                .run(args.toArray(String[]::new));
    }

    @Test
    void indexServedOnAdminPortWithSecurityHeaders() throws Exception {
        Raw r = raw(ports.admin(), "/");
        assertThat(r.status()).isEqualTo(200);
        assertThat(r.body()).isEqualTo(INDEX);
        assertThat(r.header("content-type")).startsWith("text/html");
        assertThat(r.header("x-content-type-options")).isEqualTo("nosniff");
        assertThat(r.header("x-frame-options")).isEqualTo("DENY");
        assertThat(r.header("referrer-policy")).isEqualTo("no-referrer");
        String csp = r.header("content-security-policy");
        assertThat(csp).contains("default-src 'self'").contains("frame-ancestors 'none'").contains("base-uri 'none'")
                .contains("form-action 'self'").contains("connect-src 'self'")
                .doesNotContain("'unsafe-inline'; frame").doesNotContain("script-src 'self' 'unsafe-inline'");
        // DECISIONS #52: the one inline script is allowed by its hash, not by 'unsafe-inline'.
        String expected = java.util.Base64.getEncoder().encodeToString(java.security.MessageDigest
                .getInstance("SHA-256").digest("self.__boot=1".getBytes(StandardCharsets.UTF_8)));
        assertThat(csp).contains("script-src 'self' 'sha256-" + expected + "'");
    }

    @Test
    void headMirrorsGetHeaders() throws Exception {
        Raw get = raw(ports.admin(), "/");
        Raw head = rawMethod("HEAD", ports.admin(), "/");
        assertThat(head.status()).isEqualTo(200);
        assertThat(head.header("content-security-policy")).isEqualTo(get.header("content-security-policy"));
        assertThat(head.header("x-frame-options")).isEqualTo("DENY");
    }

    @Test
    void assetServed() throws Exception {
        Raw r = raw(ports.admin(), "/_next/static/x.js");
        assertThat(r.status()).isEqualTo(200);
        assertThat(r.body()).isEqualTo("console.log('x');");
        assertThat(r.header("content-type")).startsWith("text/javascript");
        assertThat(r.header("x-content-type-options")).isEqualTo("nosniff");
    }

    @Test
    void dashboardIs404OnMtlsAndPublicPorts() throws Exception {
        X509Root root = new X509Root(ctx.getBean(TrustAnchors.class).root());
        TestDevices.Leaf leaf = TestDevices.enroll(ctx, "dev_dash_ports");
        try (MtlsTestClient.Connection mtls = MtlsTestClient.connect(ports.mtls(), root.cert(),
                leaf.keyPair().getPrivate(), leaf.chain())) {
            assertThat(mtls.get("/").status()).isEqualTo(404);
            assertThat(mtls.get("/_next/static/x.js").status()).isEqualTo(404);
        }
        try (MtlsTestClient.Connection pub = MtlsTestClient.connect(ports.pub(), root.cert(), null, List.of())) {
            assertThat(pub.get("/").status()).isEqualTo(404);
            assertThat(pub.get("/_next/static/x.js").status()).isEqualTo(404);
            assertThat(pub.get("/index.html").status()).isEqualTo(404);
        }
    }

    @Test
    void traversalIs404() throws Exception {
        for (String path : List.of("/../build.gradle", "/../secret.txt", "/%2e%2e%2fsecret.txt",
                "/%2e%2e/secret.txt", "/_next/%2e%2e/%2e%2e/secret.txt", "/..%5csecret.txt", "/%00index.html")) {
            Raw r = raw(ports.admin(), path);
            assertThat(r.status()).as(path).isIn(400, 404);
            assertThat(r.body()).as(path).doesNotContain("outside the dashboard dir");
        }
    }

    @Test
    void apiStillRoutesToTheApi() throws Exception {
        Raw r = raw(ports.admin(), "/api/v1/admin/overview");
        assertThat(r.status()).isEqualTo(401); // the API (bearer required), not a static 404
        assertThat(r.header("cache-control")).isEqualTo("no-store");
        assertThat(raw(ports.admin(), "/api/v1/admin/boot-status").status()).isEqualTo(200);
    }

    @Test
    void missingDirShowsNotBuiltAndServerIsUp() throws Exception {
        TestPorts.Listeners p = TestPorts.allocate();
        ConfigurableApplicationContext noDash = startServer(dashDir.resolveSibling("does-not-exist"), p);
        try {
            Raw r = raw(p.admin(), "/");
            assertThat(r.status()).isEqualTo(200);
            assertThat(r.body()).contains("dashboard not built: run npm run build in dashboard/");
            assertThat(raw(p.admin(), "/_next/static/x.js").status()).isEqualTo(404);
            assertThat(raw(p.admin(), "/api/v1/admin/boot-status").status()).isEqualTo(200);
        } finally {
            noDash.close();
        }
    }

    // ---- raw HTTP/1.1 over a plain socket, so paths like /../ reach the server unnormalized ----------------------

    record X509Root(java.security.cert.X509Certificate cert) {
    }

    record Raw(int status, Map<String, String> headers, String body) {
        String header(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }
    }

    static Raw raw(int port, String path) throws IOException {
        return rawMethod("GET", port, path);
    }

    static Raw rawMethod(String method, int port, String path) throws IOException {
        try (Socket s = new Socket(InetAddress.getLoopbackAddress(), port)) {
            s.setSoTimeout(5000);
            OutputStream out = s.getOutputStream();
            out.write((method + " " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            out.flush();
            InputStream in = s.getInputStream();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            in.transferTo(buf);
            String all = buf.toString(StandardCharsets.UTF_8);
            int split = all.indexOf("\r\n\r\n");
            String head = split < 0 ? all : all.substring(0, split);
            String body = split < 0 ? "" : all.substring(split + 4);
            String[] lines = head.split("\r\n");
            int status = Integer.parseInt(lines[0].split(" ")[1]);
            Map<String, String> headers = new LinkedHashMap<>();
            boolean chunked = false;
            for (int i = 1; i < lines.length; i++) {
                int c = lines[i].indexOf(':');
                if (c > 0) {
                    String k = lines[i].substring(0, c).trim().toLowerCase(Locale.ROOT);
                    String v = lines[i].substring(c + 1).trim();
                    headers.put(k, v);
                    chunked |= k.equals("transfer-encoding") && v.contains("chunked");
                }
            }
            if (chunked) {
                StringBuilder sb = new StringBuilder();
                String rest = body;
                while (true) {
                    int eol = rest.indexOf("\r\n");
                    int size = Integer.parseInt(rest.substring(0, eol).trim(), 16);
                    if (size == 0) {
                        break;
                    }
                    sb.append(rest, eol + 2, eol + 2 + size);
                    rest = rest.substring(eol + 2 + size + 2);
                }
                body = sb.toString();
            }
            return new Raw(status, headers, body);
        }
    }
}
