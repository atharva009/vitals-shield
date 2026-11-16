package com.vitalsshield.server.admin.webauthn;

/**
 * Signature counter rule (DECISIONS #61). Synced platform passkeys (iCloud Keychain) always report 0, so 0 is
 * accepted; any non-zero counter must be strictly greater than the stored one, else the assertion is rejected as a
 * possible clone.
 */
public final class CounterRule {

    private CounterRule() {
    }

    public static boolean accept(long stored, long presented) {
        return presented == 0 || presented > stored;
    }

    /** The value to store after an accepted assertion. */
    public static long next(long stored, long presented) {
        return Math.max(stored, presented);
    }
}
