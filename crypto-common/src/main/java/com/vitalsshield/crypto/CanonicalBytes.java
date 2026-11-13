package com.vitalsshield.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * Builder for the spec Section 3 canonical binary encodings. Every multi-field
 * signed payload is assembled through this class so fields carry explicit
 * big-endian length prefixes or fixed-width digests.
 *
 * <p>Not thread-safe; create one instance per encoding.
 */
public final class CanonicalBytes {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    /** Appends {@code value} as 4 bytes, big-endian. The int's bits are written as-is (unsigned view). */
    public CanonicalBytes uint32Be(int value) {
        out.write(value >>> 24);
        out.write(value >>> 16);
        out.write(value >>> 8);
        out.write(value);
        return this;
    }

    /** Appends {@code value} as 8 bytes, big-endian two's complement. */
    public CanonicalBytes int64Be(long value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.write((int) (value >>> shift));
        }
        return this;
    }

    /** Appends {@code uint32_be(len(utf8(value))) || utf8(value)}; the length is in bytes. */
    public CanonicalBytes utf8WithLength(String value) {
        Objects.requireNonNull(value, "value");
        byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
        uint32Be(utf8.length);
        out.writeBytes(utf8);
        return this;
    }

    /** Appends the 32-byte SHA-256 digest of {@code data}. */
    public CanonicalBytes sha256(byte[] data) {
        Objects.requireNonNull(data, "data");
        out.writeBytes(sha256Digest().digest(data));
        return this;
    }

    /** Appends {@code data} verbatim with no length prefix. */
    public CanonicalBytes raw(byte[] data) {
        Objects.requireNonNull(data, "data");
        out.writeBytes(data);
        return this;
    }

    public byte[] toByteArray() {
        return out.toByteArray();
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is mandatory in every JRE", e);
        }
    }
}
