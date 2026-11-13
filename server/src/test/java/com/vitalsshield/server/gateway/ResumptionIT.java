package com.vitalsshield.server.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.Pems;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.signer.SignerRevocationService;
import com.vitalsshield.server.testsupport.TestDevices;
import com.vitalsshield.server.testsupport.TestDevices.Leaf;
import com.vitalsshield.server.testsupport.TestPorts;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Tries TLS 1.3 session resumption with OpenSSL s_client against the mTLS listener, before and after a revoke, and
 * records which defense stopped the resumed connection. Results go to build/mtls-out/resumption-result.txt.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class ResumptionIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-resumption-it");
        registry.add("vitalsshield.pki.trust-file", () -> dir.resolve("root-ca.pem").toString());
        ports = TestPorts.register(registry);
    }

    @Autowired ApplicationContext ctx;
    @Autowired SignerRevocationService revocations;
    @Autowired PostHandshakeGate gate;
    @Autowired TrustAnchors anchors;

    record Run(String sessionKind, int ticketsArrived, Integer httpStatus, String output) {
        boolean got200() {
            return httpStatus != null && httpStatus == 200;
        }
    }

    @Test
    void resumedSessionNeverReaches200AfterRevoke() throws Exception {
        String openssl = findOpenssl();
        Assumptions.assumeTrue(openssl != null, "OpenSSL 3 not found: set OPENSSL_BIN; skipping ResumptionIT");

        Path out = Path.of(System.getProperty("vitalsshield.repoRoot", "..")).resolve("build/mtls-out");
        Files.createDirectories(out);
        Leaf leaf = TestDevices.enroll(ctx, "dev_resume");
        Files.writeString(out.resolve("root.pem"), Pems.certificate(anchors.root()));
        Files.writeString(out.resolve("leaf.pem"), Pems.certificate(leaf.cert()));
        Files.writeString(out.resolve("leaf-key.pem"), "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(leaf.keyPair().getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n");

        // Baseline: does the JDK server resume at all under our settings? (no revoke in between)
        Run baseline1 = sClient(openssl, out, "-sess_out", "baseline.sess");
        Run baseline2 = sClient(openssl, out, "-sess_in", "baseline.sess");

        // The real check: fresh session, revoke, then try to resume it.
        Run first = sClient(openssl, out, "-sess_out", "sess.pem");
        assertThat(first.got200()).as("first connection pings 200:\n%s", first.output()).isTrue();

        revocations.revoke(leaf.key(), "KEY_COMPROMISE").block(Duration.ofSeconds(10));
        long gateBefore = gate.postHandshakeRejects();
        Run second = sClient(openssl, out, "-sess_in", "sess.pem");
        long gateDelta = gate.postHandshakeRejects() - gateBefore;

        String defense;
        if (second.got200()) {
            defense = "NONE (resumed connection got HTTP 200)";
        } else if (second.httpStatus() != null && second.httpStatus() == 403) {
            defense = "PER_REQUEST_403";
        } else if ("Reused".equals(second.sessionKind()) || gateDelta > 0) {
            defense = "POST_HANDSHAKE_GATE (session resumed, then closed)";
        } else {
            defense = "HANDSHAKE_REFUSED (no resumption; full handshake rejected by the trust manager)";
        }

        String result = String.format("""
                RESUMPTION_BASELINE first=%s tickets=%d http=%s | resume=%s tickets=%d http=%s
                RESUMPTION_AFTER_REVOKE first=%s tickets=%d http=%s | resume=%s http=%s postHandshakeRejectsDelta=%d
                RESUMPTION_RESULT defense=%s
                """,
                baseline1.sessionKind(), baseline1.ticketsArrived(), baseline1.httpStatus(),
                baseline2.sessionKind(), baseline2.ticketsArrived(), baseline2.httpStatus(),
                first.sessionKind(), first.ticketsArrived(), first.httpStatus(),
                second.sessionKind(), second.httpStatus(), gateDelta, defense);
        System.out.print(result);
        Files.writeString(out.resolve("resumption-result.txt"), result);
        Files.writeString(out.resolve("resumption-second-attempt.txt"), second.output());
        Files.writeString(out.resolve("resumption-baseline-resume.txt"), baseline2.output());

        assertThat(second.got200()).as("resumed connection after revoke:\n%s", second.output()).isFalse();
    }

    private Run sClient(String openssl, Path dir, String sessFlag, String sessFile) throws Exception {
        List<String> cmd = new ArrayList<>(List.of(openssl, "s_client", "-tls1_3",
                "-connect", "127.0.0.1:" + ports.mtls(), "-servername", "localhost",
                "-cert", "leaf.pem", "-key", "leaf-key.pem", "-CAfile", "root.pem",
                sessFlag, sessFile, "-ign_eof"));
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        try (OutputStream stdin = p.getOutputStream()) {
            stdin.write("GET /api/v1/telemetry/ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    .getBytes(StandardCharsets.US_ASCII));
        }
        String output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!p.waitFor(20, TimeUnit.SECONDS)) {
            p.destroyForcibly();
        }
        Matcher kind = Pattern.compile("^(New|Reused), TLSv1\\.3", Pattern.MULTILINE).matcher(output);
        Matcher http = Pattern.compile("^HTTP/1\\.1 (\\d{3})", Pattern.MULTILINE).matcher(output);
        int tickets = output.split("Post-Handshake New Session Ticket arrived", -1).length - 1;
        return new Run(kind.find() ? kind.group(1) : "none", tickets,
                http.find() ? Integer.parseInt(http.group(1)) : null, output);
    }

    private static String findOpenssl() {
        String env = System.getenv("OPENSSL_BIN");
        if (env != null && !env.isBlank()) {
            return Files.isExecutable(Path.of(env)) ? env : null;
        }
        try {
            Process p = new ProcessBuilder("brew", "--prefix", "openssl@3").redirectErrorStream(true).start();
            String prefix = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            if (p.waitFor(30, TimeUnit.SECONDS) && p.exitValue() == 0) {
                Path bin = Path.of(prefix, "bin", "openssl");
                return Files.isExecutable(bin) ? bin.toString() : null;
            }
        } catch (IOException | InterruptedException e) {
            // brew missing
        }
        return null;
    }
}
