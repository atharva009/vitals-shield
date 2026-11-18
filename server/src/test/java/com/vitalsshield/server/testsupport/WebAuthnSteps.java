package com.vitalsshield.server.testsupport;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** The admin-plane ceremonies, driven with a {@link SoftwareAuthenticator}, as the dashboard drives them. */
public final class WebAuthnSteps {

    private WebAuthnSteps() {
    }

    public static String setupCode(Path file) {
        try {
            return Files.readString(file).trim();
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    /** register/begin + finish; returns the finish response. Uses the bearer only if given. */
    public static AdminHttp.Response register(AdminHttp http, SoftwareAuthenticator a, String clinicianId,
                                              String bearerOrNull, SoftwareAuthenticator.Variant v) {
        AdminHttp.Response begin = http.post("/api/v1/admin/passkeys/register/begin",
                AdminHttp.json(Map.of("clinician_id", clinicianId, "display_name", clinicianId)), http.origin(),
                bearerOrNull);
        if (begin.status() != 200) {
            return begin;
        }
        return http.post("/api/v1/admin/passkeys/register/finish",
                SoftwareAuthenticator.finishBody(a.register(begin.body(), v), null));
    }

    public static AdminHttp.Response register(AdminHttp http, SoftwareAuthenticator a, String clinicianId,
                                              String bearerOrNull) {
        return register(http, a, clinicianId, bearerOrNull, SoftwareAuthenticator.Variant.good(http.origin()));
    }

    public static AdminHttp.Response signIn(AdminHttp http, SoftwareAuthenticator a, SoftwareAuthenticator.Variant v) {
        AdminHttp.Response begin = http.post("/api/v1/admin/session/begin", "{}");
        assertThat(begin.status()).as(begin.body()).isEqualTo(200);
        return http.post("/api/v1/admin/session/finish",
                SoftwareAuthenticator.finishBody(a.assert_(begin.body(), v), null));
    }

    public static AdminHttp.Response signIn(AdminHttp http, SoftwareAuthenticator a) {
        return signIn(http, a, SoftwareAuthenticator.Variant.good(http.origin()));
    }

    /** First clinician: register with the setup code, then sign in. */
    public static void bootstrapClinician(AdminHttp http, SoftwareAuthenticator a, String clinicianId, Path codeFile) {
        AdminHttp.Response reg = register(http, a, clinicianId, setupCode(codeFile));
        assertThat(reg.status()).as(reg.body()).isEqualTo(200);
        AdminHttp.Response in = signIn(http, a);
        assertThat(in.status()).as(in.body()).isEqualTo(200);
    }

    /** begin + finish for a ceremony-id step (provision, quarantine, restore). */
    public static AdminHttp.Response ceremony(AdminHttp http, SoftwareAuthenticator a, String beginPath,
                                              Map<String, ?> beginBody, String finishPath,
                                              SoftwareAuthenticator.Variant v) {
        AdminHttp.Response begin = http.post(beginPath, AdminHttp.json(beginBody));
        if (begin.status() != 200) {
            return begin;
        }
        String ceremonyId = (String) begin.json().get("ceremony_id");
        return http.post(finishPath, SoftwareAuthenticator.finishBody(a.assert_(begin.body(), v), ceremonyId));
    }

    /** Provisions a device; returns the bootstrap token. */
    public static String provision(AdminHttp http, SoftwareAuthenticator a, String deviceId) {
        AdminHttp.Response r = ceremony(http, a, "/api/v1/admin/devices/provision/begin",
                Map.of("device_id", deviceId, "patient_id", "patient-" + deviceId, "patient_birth_year", 1985),
                "/api/v1/admin/devices/provision/finish", SoftwareAuthenticator.Variant.good(http.origin()));
        assertThat(r.status()).as(r.body()).isEqualTo(200);
        return (String) r.json().get("bootstrap_token");
    }

    /** Step-up restore-active (spec Section 4 recovery path 1). */
    public static AdminHttp.Response restore(AdminHttp http, SoftwareAuthenticator a, String deviceId) {
        return ceremony(http, a, "/api/v1/admin/devices/" + deviceId + "/restore-active/begin", Map.of(),
                "/api/v1/admin/devices/" + deviceId + "/restore-active/finish",
                SoftwareAuthenticator.Variant.good(http.origin()));
    }

    public static AdminHttp.Response quarantine(AdminHttp http, SoftwareAuthenticator a, String deviceId,
                                                int lookback, String reason) {
        return ceremony(http, a, "/api/v1/admin/devices/" + deviceId + "/quarantine/begin",
                Map.of("lookback_minutes", lookback, "reason", reason),
                "/api/v1/admin/devices/" + deviceId + "/quarantine/finish",
                SoftwareAuthenticator.Variant.good(http.origin()));
    }
}
