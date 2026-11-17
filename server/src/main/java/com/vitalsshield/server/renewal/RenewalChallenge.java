package com.vitalsshield.server.renewal;

import com.vitalsshield.crypto.CanonicalBytes;
import com.vitalsshield.crypto.encoding.CanonicalEncodings;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Stateless Protocol B challenge (spec Section 4, DECISIONS #81). The server stores nothing when it issues one: the
 * HMAC tag proves later that this boot issued it, for this certificate, at issued_at_ms. Replay is stopped when the
 * challenge is used, by consumed_challenge_nonces, not here.
 *
 * <pre>
 * tag = HMAC-SHA256(bootKey, utf8WithLength("vitalsshield.renew-challenge.v1") || utf8WithLength(issuer_key_hash)
 *                            || utf8WithLength(serial_number) || int64Be(issued_at_ms) || raw(nonce16))
 * </pre>
 * The boot key is 32 random bytes held only in memory, so a restart invalidates every outstanding challenge.
 */
@Component
public class RenewalChallenge {

    public static final String PURPOSE = "vitalsshield.renew-challenge.v1";
    /** |now - issued_at| must be at most this. */
    public static final Duration MAX_AGE = Duration.ofSeconds(60);

    public record Challenge(long issuedAtMs, byte[] nonce, byte[] tag) {
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final byte[] bootKey;
    private final Clock clock;

    @Autowired
    public RenewalChallenge(Clock clock) {
        this(randomKey(), clock);
    }

    RenewalChallenge(byte[] bootKey, Clock clock) {
        if (bootKey.length != 32) {
            throw new IllegalArgumentException("boot key must be 32 bytes");
        }
        this.bootKey = bootKey.clone();
        this.clock = clock;
    }

    static byte[] randomKey() {
        byte[] k = new byte[32];
        RANDOM.nextBytes(k);
        return k;
    }

    /** A new challenge for the certificate (issuer_key_hash, serial_number) of the requesting TLS connection. */
    public Challenge issue(String issuerKeyHash, String serialNumber) {
        long issuedAtMs = clock.millis();
        byte[] nonce = new byte[CanonicalEncodings.NONCE_LENGTH];
        RANDOM.nextBytes(nonce);
        return new Challenge(issuedAtMs, nonce, tag(issuerKeyHash, serialNumber, issuedAtMs, nonce));
    }

    /** True if the tag is ours for exactly these fields and issued_at is within 60 s of now (either direction). */
    public boolean verify(String issuerKeyHash, String serialNumber, long issuedAtMs, byte[] nonce, byte[] tag) {
        if (nonce == null || nonce.length != CanonicalEncodings.NONCE_LENGTH || tag == null) {
            return false;
        }
        long age = Math.abs(clock.millis() - issuedAtMs);
        boolean fresh = age <= MAX_AGE.toMillis();
        // Constant-time comparison, and computed even when stale so timing does not reveal which check failed.
        boolean match = MessageDigest.isEqual(tag(issuerKeyHash, serialNumber, issuedAtMs, nonce), tag);
        return fresh & match;
    }

    byte[] tag(String issuerKeyHash, String serialNumber, long issuedAtMs, byte[] nonce) {
        byte[] message = new CanonicalBytes()
                .utf8WithLength(PURPOSE)
                .utf8WithLength(issuerKeyHash)
                .utf8WithLength(serialNumber)
                .int64Be(issuedAtMs)
                .raw(nonce)
                .toByteArray();
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(bootKey, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
