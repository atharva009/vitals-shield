package com.vitalsshield.server.admin.webauthn;

import com.vitalsshield.server.admin.AdminProperties;
import com.vitalsshield.server.admin.AdminSetupCode;
import com.vitalsshield.server.audit.AuditLog;
import com.vitalsshield.server.quarantine.QuarantineController;
import com.vitalsshield.server.quarantine.QuarantineService;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import tools.jackson.databind.json.JsonMapper;

/**
 * The Phase 6 admin plane (DECISIONS #4, #55 to #63). Every route except GET auth/status is 404 in bearer mode.
 * JDBC, KMS, and ceremony verification run on boundedElastic.
 */
@RestController
public class WebAuthnController {

    private static final String API = "/api/v1/admin";
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String ID_PATTERN = "[A-Za-z0-9_.@-]{1,64}";

    private final AdminProperties admin;
    private final AdminSetupCode setupCode;
    private final AdminSessionStore sessions;
    private final PasskeyRepository passkeys;
    private final WebAuthnService webauthn;
    private final ProvisioningService provisioning;
    private final StepUpService stepUp;
    private final QuarantineService quarantine;
    private final AuditLog audit;

    public WebAuthnController(AdminProperties admin, AdminSetupCode setupCode, AdminSessionStore sessions,
                              PasskeyRepository passkeys, WebAuthnService webauthn, ProvisioningService provisioning,
                              StepUpService stepUp, QuarantineService quarantine, AuditLog audit) {
        this.admin = admin;
        this.setupCode = setupCode;
        this.sessions = sessions;
        this.passkeys = passkeys;
        this.webauthn = webauthn;
        this.provisioning = provisioning;
        this.stepUp = stepUp;
        this.quarantine = quarantine;
        this.audit = audit;
    }

    // ---- status and passkeys ----------------------------------------------------------------------------------

    @GetMapping(API + "/auth/status")
    public Mono<ResponseEntity<String>> status(ServerWebExchange exchange) {
        return blocking(() -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("mode", admin.webauthn() ? "webauthn" : "bearer");
            if (admin.webauthn()) {
                m.put("passkeys_registered", passkeys.countClinicianPasskeys());
                AdminSessionStore.Session s = session(exchange);
                m.put("clinician_id", s == null ? null : s.clinicianId());
            }
            return ok(m);
        });
    }

    /** Allowed with a passkey session, or with the setup code while no clinician passkey exists (DECISIONS #60). */
    @PostMapping(API + "/passkeys/register/begin")
    public Mono<ResponseEntity<String>> registerBegin(ServerWebExchange exchange,
                                                      @RequestBody(required = false) Mono<Map<String, Object>> body) {
        if (!admin.webauthn()) {
            return notFound();
        }
        String bearer = AdminSessionWebFilter.bearer(exchange.getRequest());
        AdminSessionStore.Session session = session(exchange);
        return json(body).flatMap(b -> blocking(() -> {
            boolean firstWithCode = session == null && bearer != null && setupCode.matches(bearer)
                    && passkeys.countClinicianPasskeys() == 0;
            if (session == null && !firstWithCode) {
                return ResponseEntity.status(401).<String>build();
            }
            String clinicianId = str(b, "clinician_id");
            String displayName = str(b, "display_name");
            if (clinicianId == null || !clinicianId.matches(ID_PATTERN) || displayName == null || displayName.isBlank()
                    || displayName.length() > 128) {
                return error(400, "VALIDATION_FAILED");
            }
            return okRaw("{\"options\":" + webauthn.registerBegin(clinicianId, displayName) + "}");
        }));
    }

    @PostMapping(API + "/passkeys/register/finish")
    public Mono<ResponseEntity<String>> registerFinish(@RequestBody(required = false) Mono<Map<String, Object>> body) {
        if (!admin.webauthn()) {
            return notFound();
        }
        return json(body).flatMap(b -> blocking(() -> {
            WebAuthnService.Registered r = webauthn.registerFinish(credential(b));
            return ok(Map.of("clinician_id", r.clinicianId(), "credential_id", r.credentialId()));
        }));
    }

    // ---- session ----------------------------------------------------------------------------------------------

    @PostMapping(API + "/session/begin")
    public Mono<ResponseEntity<String>> sessionBegin() {
        if (!admin.webauthn()) {
            return notFound();
        }
        return blocking(() -> okRaw("{\"options\":" + webauthn.signInBegin() + "}"));
    }

    @PostMapping(API + "/session/finish")
    public Mono<ResponseEntity<String>> sessionFinish(@RequestBody(required = false) Mono<Map<String, Object>> body) {
        if (!admin.webauthn()) {
            return notFound();
        }
        return json(body).flatMap(b -> blocking(() -> {
            WebAuthnService.VerifiedAssertion a = webauthn.signInFinish(credential(b));
            AdminSessionStore.Session s = sessions.create(a.clinicianId(), a.credentialId());
            ResponseCookie cookie = ResponseCookie.from(AdminSessionStore.COOKIE, s.id())
                    .httpOnly(true).sameSite("Strict").path(API).build();
            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(JSON.writeValueAsString(Map.of("clinician_id", a.clinicianId())));
        }));
    }

    @PostMapping(API + "/session/logout")
    public Mono<ResponseEntity<String>> logout(ServerWebExchange exchange) {
        if (!admin.webauthn()) {
            return notFound();
        }
        AdminSessionStore.Session s = session(exchange);
        if (s != null) {
            sessions.remove(s.id());
        }
        ResponseCookie gone = ResponseCookie.from(AdminSessionStore.COOKIE, "").httpOnly(true).sameSite("Strict")
                .path(API).maxAge(0).build();
        return Mono.just(ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, gone.toString())
                .contentType(MediaType.APPLICATION_JSON).body("{}"));
    }

    @GetMapping(API + "/session")
    public Mono<ResponseEntity<String>> whoAmI(ServerWebExchange exchange) {
        if (!admin.webauthn()) {
            return notFound();
        }
        AdminSessionStore.Session s = session(exchange);
        return s == null ? Mono.just(ResponseEntity.status(401).build())
                : Mono.just(ok(Map.of("clinician_id", s.clinicianId())));
    }

    // ---- provisioning -----------------------------------------------------------------------------------------

    @PostMapping(API + "/devices/provision/begin")
    public Mono<ResponseEntity<String>> provisionBegin(ServerWebExchange exchange,
                                                       @RequestBody(required = false) Mono<Map<String, Object>> body) {
        if (!admin.webauthn()) {
            return notFound();
        }
        AdminSessionStore.Session s = session(exchange);
        return json(body).flatMap(b -> blocking(() -> {
            String deviceId = str(b, "device_id");
            String patientId = str(b, "patient_id");
            String model = b.get("hardware_model") instanceof String m ? m : "vitalsshield-sim-v1";
            Object year = b.get("patient_birth_year");
            Object days = b.getOrDefault("max_renewal_days", 30);
            if (deviceId == null || !deviceId.matches(ID_PATTERN) || patientId == null || !patientId.matches(ID_PATTERN)
                    || !model.matches(ID_PATTERN) || !(year instanceof Integer y) || y < 1900 || y > 2100
                    || !(days instanceof Integer d) || d < 1 || d > 365) {
                return error(400, "VALIDATION_FAILED");
            }
            ProvisioningService.Begun begun = provisioning.begin(s.clinicianId(), s.credentialId(),
                    new ProvisioningService.BeginRequest(deviceId, model, patientId, y, d));
            return okRaw(ceremonyJson(begun.ceremonyId(), begun.optionsJson()));
        }));
    }

    @PostMapping(API + "/devices/provision/finish")
    public Mono<ResponseEntity<String>> provisionFinish(ServerWebExchange exchange,
                                                        @RequestBody(required = false) Mono<Map<String, Object>> body) {
        if (!admin.webauthn()) {
            return notFound();
        }
        AdminSessionStore.Session s = session(exchange);
        return json(body).flatMap(b -> blocking(() -> ok(
                provisioning.finish(s.clinicianId(), str(b, "ceremony_id"), credential(b)).toJson())));
    }

    @PostMapping(API + "/assignments/{assignmentId}/close")
    public Mono<ResponseEntity<String>> closeAssignment(ServerWebExchange exchange, @PathVariable String assignmentId) {
        if (!admin.webauthn()) {
            return notFound();
        }
        AdminSessionStore.Session s = session(exchange);
        return blocking(() -> {
            UUID id;
            try {
                id = UUID.fromString(assignmentId);
            } catch (IllegalArgumentException e) {
                return error(400, "VALIDATION_FAILED");
            }
            return provisioning.closeAssignment(s.clinicianId(), id)
                    ? ok(Map.of("assignment_id", id.toString(), "status", "CLOSED"))
                    : error(404, "NO_ACTIVE_ASSIGNMENT");
        });
    }

    // ---- step-up actions --------------------------------------------------------------------------------------

    @PostMapping(API + "/devices/{deviceId}/quarantine/begin")
    public Mono<ResponseEntity<String>> quarantineBegin(ServerWebExchange exchange, @PathVariable String deviceId,
                                                        @RequestBody(required = false) Mono<Map<String, Object>> body) {
        if (!admin.webauthn()) {
            return notFound();
        }
        AdminSessionStore.Session s = session(exchange);
        return json(body).flatMap(b -> blocking(() -> QuarantineController.validate(deviceId, b)
                .map(p -> {
                    StepUpService.Begun begun = stepUp.beginQuarantine(s, p);
                    return okRaw(ceremonyJson(begun.ceremonyId(), begun.optionsJson()));
                })
                .orElseGet(() -> error(400, "VALIDATION_FAILED"))));
    }

    /** Runs the Phase 4 quarantine with the parameters stored at begin, never parameters from this request. */
    @PostMapping(API + "/devices/{deviceId}/quarantine/finish")
    public Mono<ResponseEntity<String>> quarantineFinish(ServerWebExchange exchange, @PathVariable String deviceId,
                                                         @RequestBody(required = false) Mono<Map<String, Object>> body) {
        if (!admin.webauthn()) {
            return notFound();
        }
        AdminSessionStore.Session s = session(exchange);
        return json(body)
                .flatMap(b -> Mono.fromCallable(() -> stepUp.finish(s, StepUpService.Purpose.QUARANTINE, deviceId,
                                str(b, "ceremony_id"), credential(b)))
                        .subscribeOn(Schedulers.boundedElastic()))
                .flatMap(approved -> quarantine.quarantine(approved.deviceId(), approved.params().lookbackMinutes(),
                                approved.params().reason(), new QuarantineService.Approval(
                                        approved.assertion().clinicianId(), approved.assertion().sha256Hex()))
                        .map(res -> {
                            Map<String, Object> out = new LinkedHashMap<>(res.toJson());
                            out.put("approved_by", approved.assertion().clinicianId());
                            return ok(out);
                        }))
                .onErrorResume(WebAuthnFailure.class, e -> Mono.just(error(e.status(), e.code())))
                .onErrorResume(QuarantineService.StateConflict.class, e -> {
                    ResponseEntity<Map<String, Object>> c = QuarantineController.conflict(e);
                    return Mono.just(ResponseEntity.status(c.getStatusCode()).contentType(MediaType.APPLICATION_JSON)
                            .body(JSON.writeValueAsString(c.getBody())));
                });
    }

    @PostMapping(API + "/devices/{deviceId}/restore-active/begin")
    public Mono<ResponseEntity<String>> restoreBegin(ServerWebExchange exchange, @PathVariable String deviceId) {
        if (!admin.webauthn()) {
            return notFound();
        }
        AdminSessionStore.Session s = session(exchange);
        return blocking(() -> {
            StepUpService.Begun begun = stepUp.beginRestore(s, deviceId);
            return okRaw(ceremonyJson(begun.ceremonyId(), begun.optionsJson()));
        });
    }

    @PostMapping(API + "/devices/{deviceId}/restore-active/finish")
    public Mono<ResponseEntity<String>> restoreFinish(ServerWebExchange exchange, @PathVariable String deviceId,
                                                      @RequestBody(required = false) Mono<Map<String, Object>> body) {
        if (!admin.webauthn()) {
            return notFound();
        }
        AdminSessionStore.Session s = session(exchange);
        return json(body).flatMap(b -> blocking(() -> ok(stepUp.restore(stepUp.finish(s,
                StepUpService.Purpose.RESTORE_ACTIVE, deviceId, str(b, "ceremony_id"), credential(b))))));
    }

    // ---- audit ------------------------------------------------------------------------------------------------

    @GetMapping(API + "/audit")
    public Mono<ResponseEntity<String>> audit(@RequestParam(defaultValue = "50") int limit) {
        if (!admin.webauthn()) {
            return notFound();
        }
        return blocking(() -> {
            AuditLog.Verification v = audit.verify();
            List<Map<String, Object>> entries = new ArrayList<>();
            for (AuditLog.Entry e : audit.latest(Math.max(1, Math.min(limit, 200)))) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("sequence_id", e.sequenceId());
                m.put("event_type", e.eventType());
                m.put("actor_id", e.actorId());
                m.put("payload", e.payload());
                m.put("prev_entry_hash", e.prevHash());
                m.put("entry_hash", e.entryHash());
                m.put("created_at", e.createdAt().toString());
                entries.add(m);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("chain_valid", v.valid());
            out.put("first_broken_sequence_id", v.firstBrokenSequenceId());
            out.put("total_entries", v.entries());
            out.put("entries", entries);
            return ok(out);
        });
    }

    // ---- helpers ----------------------------------------------------------------------------------------------

    private static AdminSessionStore.Session session(ServerWebExchange exchange) {
        return exchange.getAttribute(AdminSessionWebFilter.SESSION_ATTR);
    }

    private static Mono<Map<String, Object>> json(Mono<Map<String, Object>> body) {
        return body == null ? Mono.just(Map.of()) : body.defaultIfEmpty(Map.of()).onErrorReturn(Map.of());
    }

    private static Mono<ResponseEntity<String>> blocking(Callable<ResponseEntity<String>> work) {
        return Mono.fromCallable(work).subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(WebAuthnFailure.class, e -> Mono.just(error(e.status(), e.code())));
    }

    private static String credential(Map<String, Object> body) {
        Object c = body.get("credential");
        if (!(c instanceof Map<?, ?>)) {
            throw new WebAuthnFailure(400, "MALFORMED_CREDENTIAL", "credential object missing");
        }
        return JSON.writeValueAsString(c);
    }

    private static String str(Map<String, Object> b, String key) {
        return b.get(key) instanceof String s ? s : null;
    }

    private static String ceremonyJson(String ceremonyId, String optionsJson) {
        return "{\"ceremony_id\":" + JSON.writeValueAsString(ceremonyId) + ",\"options\":" + optionsJson + "}";
    }

    private static ResponseEntity<String> ok(Map<String, ?> body) {
        return okRaw(JSON.writeValueAsString(body));
    }

    private static ResponseEntity<String> okRaw(String json) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(json);
    }

    static ResponseEntity<String> error(int status, String code) {
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON)
                .body("{\"error\":\"" + code + "\"}");
    }

    private static Mono<ResponseEntity<String>> notFound() {
        return Mono.just(ResponseEntity.notFound().build());
    }
}
