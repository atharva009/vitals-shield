package com.vitalsshield.server.testsupport;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;
import org.springframework.test.context.DynamicPropertyRegistry;

/** Free ephemeral ports, so integration tests never collide with a running bootRun on 8443-8445. */
public final class TestPorts {

    /**
     * Phase 2 to 5 tests run in bearer mode, the Phase 5 behavior they assert (DECISIONS #64); Phase 6 tests and the
     * e2e tier use {@link #registerWebAuthn} or {@link #asArgs(String)} with "webauthn".
     */
    public record Listeners(int mtls, int pub, int admin, java.nio.file.Path adminCodeFile) {
        public List<String> asArgs() {
            return asArgs("bearer");
        }

        public List<String> asArgs(String authMode) {
            return List.of(
                    "--vitalsshield.admin.auth=" + authMode,
                    "--vitalsshield.admin.setup-code-file=" + adminCodeFile,
                    "--vitalsshield.listeners.bind-host=127.0.0.1",
                    "--vitalsshield.listeners.mtls-port=" + mtls,
                    "--vitalsshield.listeners.public-port=" + pub,
                    "--vitalsshield.listeners.admin-port=" + admin);
        }
    }

    private TestPorts() {
    }

    /** A fresh temp path for the admin setup code, so tests never write into the repo's var/. */
    public static java.nio.file.Path adminCodeFile() {
        try {
            return java.nio.file.Files.createTempDirectory("vs-admin").resolve("setup-code");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static Listeners allocate() {
        List<ServerSocket> held = new ArrayList<>();
        try {
            for (int i = 0; i < 3; i++) {
                held.add(new ServerSocket(0, 1, InetAddress.getLoopbackAddress()));
            }
            return new Listeners(held.get(0).getLocalPort(), held.get(1).getLocalPort(), held.get(2).getLocalPort(),
                    adminCodeFile());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } finally {
            held.forEach(s -> {
                try {
                    s.close();
                } catch (IOException ignored) {
                    // best effort
                }
            });
        }
    }

    /** For @SpringBootTest classes: registers three fresh ports, bearer mode. */
    public static Listeners register(DynamicPropertyRegistry registry) {
        return register(registry, "bearer");
    }

    /** As {@link #register(DynamicPropertyRegistry)}, in webauthn mode. */
    public static Listeners registerWebAuthn(DynamicPropertyRegistry registry) {
        return register(registry, "webauthn");
    }

    private static Listeners register(DynamicPropertyRegistry registry, String authMode) {
        Listeners l = allocate();
        registry.add("vitalsshield.admin.auth", () -> authMode);
        registry.add("vitalsshield.admin.setup-code-file", () -> l.adminCodeFile().toString());
        registry.add("vitalsshield.listeners.bind-host", () -> "127.0.0.1");
        registry.add("vitalsshield.listeners.mtls-port", l::mtls);
        registry.add("vitalsshield.listeners.public-port", l::pub);
        registry.add("vitalsshield.listeners.admin-port", l::admin);
        return l;
    }
}
