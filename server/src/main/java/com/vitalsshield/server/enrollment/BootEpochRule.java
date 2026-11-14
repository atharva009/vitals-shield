package com.vitalsshield.server.enrollment;

/**
 * Protocol A epoch rule (spec Section 4, DECISIONS #31). boot_epoch is server-assigned: a device that has never had a
 * certificates row keeps its stored epoch (1 for a new device); any re-provisioned device gets stored + 1, so its new
 * telemetry can never collide with sequence numbers it used before. The replay window always restarts.
 */
public final class BootEpochRule {

    public record DeviceCounters(long bootEpoch, long lastSequenceNum, long replayBitmap) {
    }

    private BootEpochRule() {
    }

    public static DeviceCounters afterEnrollment(long storedBootEpoch, boolean hasPriorCertificate) {
        long epoch = hasPriorCertificate ? storedBootEpoch + 1 : storedBootEpoch;
        return new DeviceCounters(epoch, 0, 0);
    }
}
