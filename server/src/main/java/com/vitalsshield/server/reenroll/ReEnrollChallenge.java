package com.vitalsshield.server.reenroll;

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
 * Stateless Protocol C challenge (spec Section 4, DECISIONS #90). Nothing is stored when one is issued; the tag proves
 * later that this boot issued it, for this device_id, at issued_at_ms. Replay is stopped by consumed_challenge_nonces
 * when the challenge is spent.
 *
 * <pre>
 * tag = HMAC-SHA256(bootKey, utf8WithLength("vitalsshield.reenroll-challenge.v1") || utf8WithLength(device_id)
 *                            || int64Be(issued_at_ms) || raw(nonce16))
 * </pre>
 * The boot key is 32 random bytes in memory, separate from the Protocol B key, so neither challenge verifies as the
 * other even with the same fields.
 */
@Component
public class ReEnrollChallenge {

    public static final String PURPOSE = "vitalsshield.reenroll-challenge.v1";

    public record Challenge(long issuedAtMs, byte[] nonce, byte[] tag) {
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final byte[] bootKey;
    private final Clock clock;
    private final Duration maxAge;

    @Autowired
    public ReEnrollChallenge(Clock clock, ReEnrollProperties props) {
        this(randomKey(), clock, props.challengeMaxAge());
    }

    ReEnrollChallenge(byte[] bootKey, Clock clock, Duration maxAge) {
        if (bootKey.length != 32) {
            throw new IllegalArgumentException("boot key must be 32 bytes");
        }
        this.bootKey = bootKey.clone();
        this.clock = clock;
        this.maxAge = maxAge;
    }

    static byte[] randomKey() {
        byte[] k = new byte[32];
        RANDOM.nextBytes(k);
        return k;
    }

    public Challenge issue(String deviceId) {
        long issuedAtMs = clock.millis();
        byte[] nonce = new byte[CanonicalEncodings.NONCE_LENGTH];
        RANDOM.nextBytes(nonce);
        return new Challenge(issuedAtMs, nonce, tag(deviceId, issuedAtMs, nonce));
    }

    /** True if the tag is ours for exactly these fields and issued_at_ms is within max-age of JVM now. */
    public boolean verify(String deviceId, long issuedAtMs, byte[] nonce, byte[] tag) {
        if (deviceId == null || nonce == null || nonce.length != CanonicalEncodings.NONCE_LENGTH || tag == null) {
            return false;
        }
        boolean fresh = Math.abs(clock.millis() - issuedAtMs) <= maxAge.toMillis();
        // Constant-time, and computed even when stale so the timing does not say which check failed.
        boolean match = MessageDigest.isEqual(tag(deviceId, issuedAtMs, nonce), tag);
        return fresh & match;
    }

    byte[] tag(String deviceId, long issuedAtMs, byte[] nonce) {
        byte[] message = new CanonicalBytes()
                .utf8WithLength(PURPOSE)
                .utf8WithLength(deviceId)
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
