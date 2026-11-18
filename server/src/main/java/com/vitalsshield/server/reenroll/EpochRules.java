package com.vitalsshield.server.reenroll;

/**
 * Protocol C epoch handling (spec Section 4; DECISIONS #97). {@code s} is the stored boot_epoch, {@code p} the one the
 * device presents. The server assigns epochs; a device only ever presents the last one it was given.
 * <ul>
 *   <li>p &gt; s: INVALID. No device can hold an epoch the server never assigned: forged or corrupted state.</li>
 *   <li>resync allowed and p &lt;= s: RESYNC to s + 1 with a fresh sequence window. A clinician restored the device
 *       after a state reset (it lost its epoch and sequence numbers), so its old values cannot be trusted.</li>
 *   <li>p &lt; s otherwise: REGRESSION. An old copy of the device state (a clone, or a restored backup) is talking.</li>
 *   <li>p == s: SAME. Normal recovery from offline expiry: epoch, sequence and bitmap are kept.</li>
 * </ul>
 */
public final class EpochRules {

    public enum Kind { SAME, RESYNC, INVALID, REGRESSION }

    public record Decision(Kind kind, long assignedEpoch) {
    }

    private EpochRules() {
    }

    public static Decision decide(long stored, long presented, boolean resyncAllowed) {
        if (presented > stored) {
            return new Decision(Kind.INVALID, stored);
        }
        if (resyncAllowed) {
            return new Decision(Kind.RESYNC, stored + 1);
        }
        if (presented < stored) {
            return new Decision(Kind.REGRESSION, stored);
        }
        return new Decision(Kind.SAME, stored);
    }
}
