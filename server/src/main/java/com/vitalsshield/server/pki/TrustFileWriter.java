package com.vitalsshield.server.pki;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/** Publishes the Root CA PEM atomically: temp file in the same directory, then ATOMIC_MOVE + REPLACE_EXISTING. */
final class TrustFileWriter {

    private TrustFileWriter() {
    }

    static void write(Path target, String pem) {
        Path abs = target.toAbsolutePath();
        Path dir = abs.getParent();
        Path tmp = null;
        try {
            Files.createDirectories(dir);
            tmp = Files.createTempFile(dir, "." + abs.getFileName(), ".tmp");
            Files.writeString(tmp, pem, StandardCharsets.US_ASCII);
            Files.move(tmp, abs, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            tmp = null;
        } catch (IOException e) {
            throw new UncheckedIOException("cannot write trust file " + abs, e);
        } finally {
            if (tmp != null) {
                try {
                    Files.deleteIfExists(tmp);
                } catch (IOException ignored) {
                    // best effort
                }
            }
        }
    }

    static boolean matches(Path target, String pem) {
        try {
            return Files.isRegularFile(target) && Files.readString(target, StandardCharsets.US_ASCII).equals(pem);
        } catch (IOException e) {
            return false;
        }
    }
}
