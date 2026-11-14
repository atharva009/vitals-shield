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

    public record Listeners(int mtls, int pub, int admin, java.nio.file.Path adminCodeFile) {
        public List<String> asArgs() {
            return List.of(
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

    /** For @SpringBootTest classes: registers three fresh ports. */
    public static Listeners register(DynamicPropertyRegistry registry) {
        Listeners l = allocate();
        registry.add("vitalsshield.admin.setup-code-file", () -> l.adminCodeFile().toString());
        registry.add("vitalsshield.listeners.bind-host", () -> "127.0.0.1");
        registry.add("vitalsshield.listeners.mtls-port", l::mtls);
        registry.add("vitalsshield.listeners.public-port", l::pub);
        registry.add("vitalsshield.listeners.admin-port", l::admin);
        return l;
    }
}
