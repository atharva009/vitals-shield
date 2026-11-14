package com.vitalsshield.server.telemetry;

import java.util.Map;

/** A rejected ingest: HTTP status and JSON body. */
public final class IngestRejection extends RuntimeException {

    private final int status;
    private final Map<String, Object> body;

    public IngestRejection(int status, Map<String, Object> body) {
        super(status + " " + body);
        this.status = status;
        this.body = body;
    }

    public static IngestRejection of(int status, String error) {
        return new IngestRejection(status, Map.of("error", error));
    }

    public static IngestRejection of(int status, String error, String reason) {
        return new IngestRejection(status, Map.of("error", error, "reason", reason));
    }

    public int status() {
        return status;
    }

    public Map<String, Object> body() {
        return body;
    }
}
