package com.vitalsshield.server.testsupport;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** OpenSSL 3 from OPENSSL_BIN or Homebrew (the same lookup as PkiOpensslIT). */
public final class Openssl {

    public record Result(int exit, String output) {
    }

    private Openssl() {
    }

    /** The openssl binary, or null when OpenSSL 3 is not found. */
    public static String find() {
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
            // brew not installed
        }
        return null;
    }

    /** Runs openssl in {@code dir} with {@code stdin} as input; stdout and stderr together. */
    public static Result run(String openssl, Path dir, String stdin, String... args) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(openssl);
        cmd.addAll(List.of(args));
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        p.getOutputStream().write(stdin.getBytes(StandardCharsets.US_ASCII));
        p.getOutputStream().close();
        String output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!p.waitFor(30, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IllegalStateException("openssl did not exit:\n" + output);
        }
        return new Result(p.exitValue(), output);
    }
}
