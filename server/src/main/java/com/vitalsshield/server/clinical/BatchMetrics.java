package com.vitalsshield.server.clinical;

/** The six metrics of one telemetry batch, as stored in telemetry_records. */
public record BatchMetrics(int hr, double hrv, double spo2, double perfusion, int cadence, double motion) {
}
