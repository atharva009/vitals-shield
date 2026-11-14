package com.vitalsshield.server.admin;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Boot-generated admin bearer code (DECISIONS #41), the only admin authentication until WebAuthn (Phase 6). 32 random
 * bytes, base64url, written atomically to the setup-code file with permissions 600. Only its SHA-256 stays in memory;
 * the code itself is never logged.
 */
@Component
public class AdminSetupCode {

    private static final Logger log = LoggerFactory.getLogger(AdminSetupCode.class);

    private final AdminProperties props;
    private volatile byte[] codeSha256;

    public AdminSetupCode(AdminProperties props) {
        this.props = props;
    }

    /** Generates a new code and writes it to the file. Called once per boot. */
    public synchronized void issue() {
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        String code = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        writeAtomic(props.setupCodeFile(), code + "\n");
        codeSha256 = sha256(code);
        log.info("Admin setup code written to {}", props.setupCodeFile());
    }

    /** Constant-time comparison of SHA-256 digests. False if no code has been issued. */
    public boolean matches(String presented) {
        byte[] expected = codeSha256;
        return expected != null && presented != null && MessageDigest.isEqual(expected, sha256(presented));
    }

    private static byte[] sha256(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void writeAtomic(Path target, String content) {
        Path abs = target.toAbsolutePath();
        Path tmp = null;
        try {
            Files.createDirectories(abs.getParent());
            boolean posix = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
            FileAttribute<?>[] attrs = posix
                    ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))}
                    : new FileAttribute<?>[0];
            tmp = Files.createTempFile(abs.getParent(), ".setup-code", ".tmp", attrs);
            Files.writeString(tmp, content, StandardCharsets.US_ASCII);
            Files.move(tmp, abs, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            tmp = null;
        } catch (IOException e) {
            throw new UncheckedIOException("cannot write admin setup code to " + abs, e);
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
}
