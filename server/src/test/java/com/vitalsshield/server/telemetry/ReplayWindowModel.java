package com.vitalsshield.server.telemetry;

/**
 * Pure Java model of the spec Section 5 window rule (test oracle). Accept when seq is ahead of the newest, or within
 * the 64 newest and its bit is clear. On accept: a jump of 64 or more resets the bitmap to 1; a smaller jump shifts the
 * bitmap left by the jump and sets bit 0; an older in-window seq sets bit (last - seq).
 */
final class ReplayWindowModel {

    long last;
    long bitmap;

    enum Decision { ACCEPT, DUPLICATE, TOO_OLD }

    Decision offer(long seq) {
        long behind = last - seq;
        if (seq > last) {
            long d = seq - last;
            bitmap = d >= 64 ? 1L : (bitmap << d) | 1L;
            last = seq;
            return Decision.ACCEPT;
        }
        if (behind > 63) {
            return Decision.TOO_OLD;
        }
        if (((bitmap >>> behind) & 1L) != 0) {
            return Decision.DUPLICATE;
        }
        bitmap |= 1L << behind;
        return Decision.ACCEPT;
    }
}
