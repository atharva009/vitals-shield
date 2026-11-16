package com.vitalsshield.server.clinical;

/**
 * Clinician alert actions (DECISIONS #76): ACTIVE -> ACKNOWLEDGED -> RESOLVED, and ACTIVE -> RESOLVED.
 * RETRACTED_BY_QUARANTINE and RESOLVED are final.
 */
public final class AlertTransitions {

    private AlertTransitions() {
    }

    public static boolean allowed(String from, String to) {
        return switch (to) {
            case "ACKNOWLEDGED" -> "ACTIVE".equals(from);
            case "RESOLVED" -> "ACTIVE".equals(from) || "ACKNOWLEDGED".equals(from);
            default -> false;
        };
    }
}
