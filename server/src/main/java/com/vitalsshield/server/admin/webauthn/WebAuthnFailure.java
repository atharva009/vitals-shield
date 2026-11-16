package com.vitalsshield.server.admin.webauthn;

/** A rejected ceremony. {@code status} is the HTTP status, {@code code} the JSON error code. */
public class WebAuthnFailure extends RuntimeException {

    private final int status;
    private final String code;

    public WebAuthnFailure(int status, String code, String detail) {
        super(code + ": " + detail);
        this.status = status;
        this.code = code;
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }

    /** The ceremony id or challenge is unknown, already used, or expired. */
    public static WebAuthnFailure gone() {
        return new WebAuthnFailure(410, "CEREMONY_EXPIRED", "unknown, used, or expired ceremony");
    }
}
