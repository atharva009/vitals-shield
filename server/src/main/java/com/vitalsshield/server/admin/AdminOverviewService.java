package com.vitalsshield.server.admin;

import com.vitalsshield.server.boot.BootStatusTracker;
import com.vitalsshield.server.clinical.ClinicalProperties;
import com.vitalsshield.server.enrollment.DekAnchorVerifier;
import com.vitalsshield.server.pki.CaIssuer;
import com.vitalsshield.server.pki.CaIssuerRepository;
import com.vitalsshield.server.pki.CrlService;
import com.vitalsshield.server.pki.IssuedSerialLedger;
import com.vitalsshield.server.pki.KeyPurpose;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import com.vitalsshield.server.quarantine.QuarantineService;
import com.vitalsshield.server.session.ActiveSessionRegistry;
import com.vitalsshield.server.signer.SignerRevocationService;
import com.vitalsshield.server.telemetry.TelemetryMetrics;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import com.vitalsshield.server.renewal.CertificateActivationService;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Read-only operator snapshot for GET /api/v1/admin/overview. Blocking (JDBC); callers run it on boundedElastic.
 * Field names are a contract with the dashboard.
 */
@Service
public class AdminOverviewService {

    static final Duration DEK_CACHE_TTL = Duration.ofSeconds(30);

    private record CachedVerdict(Instant at, boolean verified) {
    }

    private final JdbcTemplate jdbc;
    private final BootStatusTracker boot;
    private final KmsHealthMonitor kms;
    private final CaIssuerRepository issuers;
    private final CrlService crls;
    private final ActiveSessionRegistry sessions;
    private final CertificateDenyList denyList;
    private final TelemetryMetrics telemetry;
    private final IssuedSerialLedger ledger;
    private final SignerRevocationService revocations;
    private final QuarantineService quarantines;
    private final DekAnchorVerifier anchors;
    private final Clock clock;
    private final ClinicalProperties clinical;
    private final CertificateActivationService activation;
    private final Map<String, CachedVerdict> dekCache = new ConcurrentHashMap<>();

    public AdminOverviewService(JdbcTemplate jdbc, BootStatusTracker boot, KmsHealthMonitor kms,
                                CaIssuerRepository issuers, CrlService crls, ActiveSessionRegistry sessions,
                                CertificateDenyList denyList, TelemetryMetrics telemetry, IssuedSerialLedger ledger,
                                SignerRevocationService revocations, QuarantineService quarantines,
                                DekAnchorVerifier anchors, Clock clock, ClinicalProperties clinical,
                                CertificateActivationService activation) {
        this.clinical = clinical;
        this.activation = activation;
        this.jdbc = jdbc;
        this.boot = boot;
        this.kms = kms;
        this.issuers = issuers;
        this.crls = crls;
        this.sessions = sessions;
        this.denyList = denyList;
        this.telemetry = telemetry;
        this.ledger = ledger;
        this.revocations = revocations;
        this.quarantines = quarantines;
        this.anchors = anchors;
        this.clock = clock;
    }

    public Map<String, Object> snapshot() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("server_time", clock.instant().toString());
        out.put("boot_steps", boot.completed().stream()
                .map(s -> Map.of("step", s.step().name(), "at", s.completedAt().toString())).toList());
        out.put("kms", kms());
        out.put("ca", ca());

        Map<CertKey, Integer> live = sessions.liveCountsByKey();
        Map<String, Integer> byDevice = liveByDevice(live);
        out.put("sessions", Map.of("live_count", sessions.liveSocketCount(), "by_device", byDevice));
        out.put("deny_list_size", denyList.size());
        out.put("telemetry", telemetry());

        Map<String, Long> counts = ledger.countsByStatus();
        out.put("ledger", Map.of("recorded", counts.get("RECORDED"), "voided", counts.get("VOIDED"),
                "reserved", counts.get("RESERVED"), "invariant_violations", ledger.invariantViolations()));

        out.put("revocations", revocations.recentResults().stream().limit(20).map(r -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("serial_display", SerialDisplayFormat.toOpenSslHex(r.key().serial()));
            m.put("device_id", r.deviceId());
            m.put("reason", r.reason());
            m.put("revoked_at", r.revokedAt().toString());
            m.put("channels_closed", r.channelsClosed());
            m.put("latency_micros", r.evictionLatencyMicros());
            return m;
        }).toList());
        out.put("quarantines", quarantines.recentResults().stream().limit(20).map(QuarantineService.Result::toJson)
                .toList());
        out.put("devices", devices(byDevice));
        out.put("renewals", renewals(20));
        out.put("alerts", alertCounts());
        out.put("clinical", clinicalCounters());
        return out;
    }

    /** Newest first; {@code deviceId} null for all devices. */
    public List<Map<String, Object>> alerts(String deviceId, int limit) {
        return jdbc.query("""
                SELECT alert_id, device_id, assignment_id, baseline_version, alert_type::text AS alert_type,
                       alert_status::text AS alert_status, condition_code, triggering_batch_ids, explanation_summary,
                       created_at, retracted_at
                  FROM clinical_alerts WHERE (?::text IS NULL OR device_id = ?)
                 ORDER BY created_at DESC LIMIT ?
                """, (rs, i) -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("alert_id", rs.getString("alert_id"));
            m.put("device_id", rs.getString("device_id"));
            m.put("assignment_id", rs.getString("assignment_id"));
            m.put("alert_type", rs.getString("alert_type"));
            m.put("condition_code", rs.getString("condition_code"));
            m.put("alert_status", rs.getString("alert_status"));
            m.put("explanation", rs.getString("explanation_summary"));
            Object[] ids = (Object[]) rs.getArray("triggering_batch_ids").getArray();
            m.put("triggering_batch_count", ids.length);
            m.put("triggering_batch_ids_short", java.util.Arrays.stream(ids).map(o -> o.toString().substring(0, 8))
                    .toList());
            m.put("baseline_version", rs.getObject("baseline_version"));
            m.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
            Timestamp r = rs.getTimestamp("retracted_at");
            m.put("retracted_at", r == null ? null : r.toInstant().toString());
            return m;
        }, deviceId, deviceId, limit);
    }

    private Map<String, Object> alertCounts() {
        Map<String, Object> m = new LinkedHashMap<>();
        for (String s : List.of("ACTIVE", "ACKNOWLEDGED", "RETRACTED_BY_QUARANTINE", "RESOLVED")) {
            m.put(s.toLowerCase(java.util.Locale.ROOT), 0L);
        }
        jdbc.query("SELECT alert_status::text, count(*) FROM clinical_alerts GROUP BY alert_status", rs -> {
            m.put(rs.getString(1).toLowerCase(java.util.Locale.ROOT), rs.getLong(2));
        });
        return m;
    }

    private Map<String, Object> clinicalCounters() {
        Map<String, Long> snap = telemetry.snapshot();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("evaluations", snap.getOrDefault("clinical.evaluations", 0L));
        m.put("evaluation_failures", snap.getOrDefault("clinical.evaluation_failures", 0L));
        m.put("dedupe_suppressed", snap.getOrDefault("clinical.dedupe_suppressed", 0L));
        Map<String, Long> byType = new TreeMap<>();
        snap.forEach((k, v) -> {
            if (k.startsWith("clinical.alerts.")) {
                byType.put(k.substring("clinical.alerts.".length()), v);
            }
        });
        m.put("alerts_created", byType);
        m.put("calibration_size", clinical.calibrationSize());
        // DECISIONS #79: queue overflow and evaluations lost to a restart both show up as unevaluated rows.
        m.put("queue_overflows", snap.getOrDefault("clinical.queue_overflows", 0L));
        m.put("queue_capacity", clinical.queueCapacity());
        m.put("unevaluated_count", jdbc.queryForObject("""
                SELECT count(*) FROM telemetry_records
                 WHERE clinical_evaluated_at IS NULL AND trust_state IN ('ACCEPTED', 'SIGNAL_DEGRADED')
                """, Long.class));
        return m;
    }

    /** Newest first, at most {@code limit} rows. */
    public List<Map<String, Object>> telemetry(String deviceId, int limit) {
        return jdbc.query("""
                SELECT t.batch_id, t.sequence_number, t.boot_epoch, t.measured_at, t.ingested_at,
                       t.trust_state::text AS ts, t.heart_rate_bpm, t.spo2_pct, t.hrv_rmssd_ms, t.perfusion_index,
                       t.step_cadence_spm, t.motion_g_rms, t.activity_context, t.clinical_evaluated_at,
                       a.baseline_state::text AS bs, a.ref_hr_mean, a.ref_hr_sd, a.ref_hrv_mean, a.ref_hrv_sd,
                       a.ref_spo2_mean, a.ref_spo2_sd
                  FROM telemetry_records t
                  JOIN patient_device_assignments a ON a.assignment_id = t.assignment_id
                 WHERE t.device_id = ?
                 ORDER BY t.ingested_at DESC, t.sequence_number DESC LIMIT ?
                """, (rs, i) -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("batch_id_short", rs.getString("batch_id").substring(0, 8));
            m.put("sequence_number", rs.getLong("sequence_number"));
            m.put("measured_at", rs.getTimestamp("measured_at").toInstant().toString());
            m.put("ingested_at", rs.getTimestamp("ingested_at").toInstant().toString());
            m.put("trust_state", rs.getString("ts"));
            m.put("heart_rate_bpm", rs.getInt("heart_rate_bpm"));
            m.put("spo2_pct", rs.getDouble("spo2_pct"));
            m.put("hrv_rmssd_ms", rs.getDouble("hrv_rmssd_ms"));
            m.put("perfusion_index", rs.getDouble("perfusion_index"));
            m.put("step_cadence_spm", rs.getInt("step_cadence_spm"));
            m.put("motion_g_rms", rs.getDouble("motion_g_rms"));
            m.put("boot_epoch", rs.getLong("boot_epoch"));
            m.put("activity_context", rs.getString("activity_context"));
            m.put("clinical_evaluated", rs.getTimestamp("clinical_evaluated_at") != null);
            // z-scores against the assignment's current LOCKED baseline, for ACCEPTED rows (DECISIONS #73).
            if ("LOCKED".equals(rs.getString("bs")) && "ACCEPTED".equals(rs.getString("ts"))) {
                Map<String, Object> z = new LinkedHashMap<>();
                z.put("hr", round2((rs.getInt("heart_rate_bpm") - rs.getDouble("ref_hr_mean")) / rs.getDouble("ref_hr_sd")));
                z.put("hrv", round2((rs.getDouble("hrv_rmssd_ms") - rs.getDouble("ref_hrv_mean"))
                        / rs.getDouble("ref_hrv_sd")));
                z.put("spo2", round2((rs.getDouble("spo2_pct") - rs.getDouble("ref_spo2_mean"))
                        / rs.getDouble("ref_spo2_sd")));
                m.put("z", z);
            } else {
                m.put("z", null);
            }
            return m;
        }, deviceId, limit);
    }

    // ---- parts ---------------------------------------------------------------------------------------------------

    private Map<String, Object> kms() {
        KmsHealthMonitor.Snapshot s = kms.current();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("healthy", s.healthy());
        m.put("state", s.state().name());
        m.put("keys", s.keys().stream().map(k -> {
            Map<String, Object> km = new LinkedHashMap<>();
            km.put("purpose", k.purpose());
            km.put("arn_suffix", k.arnSuffix());
            km.put("enabled", k.enabled());
            km.put("checked_at", k.checkedAt().toString());
            if (k.error() != null) {
                km.put("error", k.error());
            }
            return km;
        }).toList());
        return m;
    }

    private Map<String, Object> ca() {
        Map<String, Object> m = new LinkedHashMap<>();
        issuers.findActive(KeyPurpose.ROOT_CA).ifPresent(c -> m.put("root", caEntry(c)));
        issuers.findActive(KeyPurpose.DEVICE_INTERMEDIATE).ifPresent(c -> {
            Map<String, Object> e = caEntry(c);
            crls.cachedIntermediate().ifPresent(crl -> {
                e.put("crl_number", crl.crlNumber());
                e.put("crl_next_update", crl.nextUpdate().toString());
                e.put("crl_entries", crl.entryCount());
            });
            m.put("device_intermediate", e);
        });
        issuers.findActive(KeyPurpose.SERVER_TLS_CA).ifPresent(c -> m.put("server_tls_ca", caEntry(c)));
        return m;
    }

    private static Map<String, Object> caEntry(CaIssuer c) {
        X509Certificate cert = c.certificate();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("subject", cert.getSubjectX500Principal().getName());
        m.put("ski_hex", c.issuerKeyHash());
        m.put("not_after", cert.getNotAfter().toInstant().toString());
        return m;
    }

    private Map<String, Object> telemetry() {
        Map<String, Long> snap = telemetry.snapshot();
        Map<String, Long> rejected = new TreeMap<>();
        Map<String, Long> conflicts = new TreeMap<>();
        long accepted = 0;
        for (Map.Entry<String, Long> e : snap.entrySet()) {
            String k = e.getKey();
            if (k.startsWith("jws_rejected.")) {
                rejected.merge(k.substring("jws_rejected.".length()), e.getValue(), Long::sum);
            } else if (k.startsWith("accepted.")) {
                accepted += e.getValue();
            } else if (k.startsWith("rejected.409.")) {
                conflicts.merge(k.substring("rejected.409.".length()), e.getValue(), Long::sum);
            }
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("jws_verified", snap.getOrDefault("jws_verified", 0L));
        m.put("jws_rejected", rejected);
        m.put("accepted", accepted);
        m.put("idempotent_retries", snap.getOrDefault("idempotent_retries", 0L));
        m.put("conflicts", conflicts);
        return m;
    }

    private Map<String, Integer> liveByDevice(Map<CertKey, Integer> live) {
        Map<String, Integer> out = new TreeMap<>();
        if (live.isEmpty()) {
            return out;
        }
        String[] serials = live.keySet().stream().map(CertKey::serial).toArray(String[]::new);
        jdbc.query("SELECT issuer_key_hash, serial_number, device_id FROM certificates WHERE serial_number = ANY(?)",
                rs -> {
                    Integer n = live.get(CertKey.of(rs.getString(1), rs.getString(2)));
                    if (n != null) {
                        out.merge(rs.getString(3), n, Integer::sum);
                    }
                }, (Object) serials);
        return out;
    }

    private List<Map<String, Object>> devices(Map<String, Integer> liveByDevice) {
        List<Map<String, Object>> out = new ArrayList<>();
        jdbc.query("""
                SELECT d.device_id, d.trust_state::text AS ts, d.boot_epoch, d.last_sequence_num, d.last_ingested_at,
                       d.dek_spki_der_b64 IS NOT NULL AS has_dek,
                       (SELECT p.purpose FROM device_bootstrap_tokens t
                          JOIN clinician_passkeys p ON p.credential_id_b64 = t.webauthn_cred_id_b64
                         WHERE t.device_id = d.device_id
                         ORDER BY t.expires_at DESC LIMIT 1) AS latest_token_purpose,
                       a.assignment_id::text AS assignment_id, a.patient_id, a.baseline_state::text AS baseline_state,
                       a.baseline_version, cardinality(a.calibration_batch_ids) AS calibration_count,
                       a.ref_hr_mean, a.ref_hr_sd, a.ref_hrv_mean, a.ref_hrv_sd, a.ref_spo2_mean, a.ref_spo2_sd,
                       a.degraded_critical_streak, a.drift_breach_streak, a.resting_since,
                       (d.trust_state = 'ACTIVE'
                        AND EXISTS (SELECT 1 FROM certificates r WHERE r.device_id = d.device_id AND r.status = 'REVOKED')
                        AND NOT EXISTS (SELECT 1 FROM certificates r WHERE r.device_id = d.device_id
                                                                         AND r.status <> 'REVOKED')) AS cert_revoked_active,
                       c.serial_number, c.not_before, c.not_after, c.status::text AS cert_status, c.cert_thumbprint_s256
                  FROM devices d
                  LEFT JOIN patient_device_assignments a ON a.device_id = d.device_id AND a.status = 'ACTIVE'
                  LEFT JOIN LATERAL (
                        SELECT * FROM certificates c WHERE c.device_id = d.device_id
                         ORDER BY (c.status = 'ACTIVE') DESC, c.not_before DESC LIMIT 1) c ON true
                 ORDER BY d.device_id
                """, rs -> {
            String id = rs.getString("device_id");
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("device_id", id);
            m.put("trust_state", rs.getString("ts"));
            m.put("boot_epoch", rs.getLong("boot_epoch"));
            m.put("last_sequence_num", rs.getLong("last_sequence_num"));
            Timestamp last = rs.getTimestamp("last_ingested_at");
            m.put("last_ingested_at", last == null ? null : last.toInstant().toString());
            // DECISIONS #51, #66: the latest token was approved by a DEV_SEED credential.
            m.put("dev_seed", "DEV_SEED".equals(rs.getString("latest_token_purpose")));
            m.put("dek_anchor_verified", rs.getBoolean("has_dek") ? dekVerified(id) : null);
            if (rs.getString("assignment_id") != null) {
                Map<String, Object> a = new LinkedHashMap<>();
                a.put("assignment_id", rs.getString("assignment_id"));
                a.put("patient_id", rs.getString("patient_id"));
                a.put("baseline_state", rs.getString("baseline_state"));
                a.put("baseline_version", rs.getInt("baseline_version"));
                a.put("calibration_count", rs.getInt("calibration_count"));
                a.put("calibration_size", clinical.calibrationSize());
                if (rs.getObject("ref_hr_mean") != null) {
                    Map<String, Object> ref = new LinkedHashMap<>();
                    ref.put("hr_mean", round2(rs.getDouble("ref_hr_mean")));
                    ref.put("hr_sd", round2(rs.getDouble("ref_hr_sd")));
                    ref.put("hrv_mean", round2(rs.getDouble("ref_hrv_mean")));
                    ref.put("hrv_sd", round2(rs.getDouble("ref_hrv_sd")));
                    ref.put("spo2_mean", round2(rs.getDouble("ref_spo2_mean")));
                    ref.put("spo2_sd", round2(rs.getDouble("ref_spo2_sd")));
                    a.put("ref", ref);
                } else {
                    a.put("ref", null);
                }
                a.put("degraded_critical_streak", rs.getInt("degraded_critical_streak"));
                a.put("drift_breach_streak", rs.getInt("drift_breach_streak"));
                Timestamp rest = rs.getTimestamp("resting_since");
                a.put("resting_since", rest == null ? null : rest.toInstant().toString());
                m.put("assignment", a);
            } else {
                m.put("assignment", null);
            }
            if (rs.getString("serial_number") != null) {
                Map<String, Object> c = new LinkedHashMap<>();
                c.put("serial_display", SerialDisplayFormat.toOpenSslHex(rs.getString("serial_number")));
                c.put("not_before", rs.getTimestamp("not_before").toInstant().toString());
                c.put("not_after", rs.getTimestamp("not_after").toInstant().toString());
                c.put("status", rs.getString("cert_status"));
                c.put("thumbprint_s256", rs.getString("cert_thumbprint_s256"));
                c.put("renewal_due_at", renewalDueAt(rs.getTimestamp("not_before").toInstant(),
                        rs.getTimestamp("not_after").toInstant()).toString());
                m.put("active_cert", c);
            } else {
                m.put("active_cert", null);
            }
            m.put("pending_cert", lifecycleCert(id, "ISSUED_PENDING_USE"));
            m.put("renewed_cert", lifecycleCert(id, "RENEWED"));
            m.put("live_sockets", liveByDevice.getOrDefault(id, 0));
            // DECISIONS #77: the certificate was revoked but the quarantine transaction did not commit.
            m.put("needs_attention", rs.getBoolean("cert_revoked_active") ? "CERT_REVOKED_STATE_ACTIVE" : null);
            out.add(m);
        });
        return out;
    }

    /** DECISIONS #83: renewal is due at not_before + 2/3 of the validity period. */
    public static Instant renewalDueAt(Instant notBefore, Instant notAfter) {
        return notBefore.plusMillis(Duration.between(notBefore, notAfter).toMillis() * 2 / 3);
    }

    /** The device's ISSUED_PENDING_USE or newest RENEWED certificate, or null. */
    private Map<String, Object> lifecycleCert(String deviceId, String status) {
        List<Map<String, Object>> rows = jdbc.query("""
                SELECT serial_number, issuer_key_hash, issued_at, not_before, not_after, grace_expires_at
                  FROM certificates WHERE device_id = ? AND status = ?::cert_status
                 ORDER BY not_before DESC LIMIT 1
                """, (rs, i) -> {
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("serial_display", SerialDisplayFormat.toOpenSslHex(rs.getString("serial_number")));
            c.put("issued_at", rs.getTimestamp("issued_at").toInstant().toString());
            c.put("not_after", rs.getTimestamp("not_after").toInstant().toString());
            Timestamp grace = rs.getTimestamp("grace_expires_at");
            c.put("grace_expires_at", grace == null ? null : grace.toInstant().toString());
            if (grace != null) {
                c.put("grace_ended", !clock.instant().isBefore(grace.toInstant()));
            }
            return c;
        }, deviceId, status);
        return rows.isEmpty() ? null : rows.get(0);
    }

    /**
     * Newest first: certificates issued by Protocol B (superseded_serial set) with their predecessor. grace_ended_at is
     * the old certificate's grace_expires_at once it has passed; sockets_closed is what the scheduled eviction closed
     * in this process (null if it has not run here).
     */
    public List<Map<String, Object>> renewals(int limit) {
        return jdbc.query("""
                SELECT n.device_id, n.serial_number AS new_serial, n.issuer_key_hash AS new_issuer, n.issued_at,
                       n.activated_at, n.status::text AS new_status, n.revocation_reason AS new_reason,
                       o.serial_number AS old_serial, o.issuer_key_hash AS old_issuer, o.grace_expires_at,
                       o.status::text AS old_status
                  FROM certificates n
                  LEFT JOIN certificates o ON o.device_id = n.device_id AND o.serial_number = n.superseded_serial
                 WHERE n.superseded_serial IS NOT NULL
                 ORDER BY n.issued_at DESC LIMIT ?
                """, (rs, i) -> {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("device_id", rs.getString("device_id"));
            String oldSerial = rs.getString("old_serial");
            r.put("old_serial_display", oldSerial == null ? null : SerialDisplayFormat.toOpenSslHex(oldSerial));
            r.put("new_serial_display", SerialDisplayFormat.toOpenSslHex(rs.getString("new_serial")));
            r.put("new_status", rs.getString("new_status"));
            r.put("new_revocation_reason", rs.getString("new_reason"));
            r.put("issued_at", rs.getTimestamp("issued_at").toInstant().toString());
            Timestamp act = rs.getTimestamp("activated_at");
            r.put("activated_at", act == null ? null : act.toInstant().toString());
            Timestamp grace = act == null ? null : rs.getTimestamp("grace_expires_at");
            r.put("grace_expires_at", grace == null ? null : grace.toInstant().toString());
            r.put("grace_ended_at", grace != null && !clock.instant().isBefore(grace.toInstant())
                    ? grace.toInstant().toString() : null);
            Integer closed = null;
            if (oldSerial != null) {
                closed = activation.graceEviction(CertKey.of(rs.getString("old_issuer"), oldSerial))
                        .map(CertificateActivationService.GraceEviction::socketsClosed).orElse(null);
            }
            r.put("grace_sockets_closed", closed);
            return r;
        }, limit);
    }

    /** Local signature check, cached per device for 30 s (the Key #4 public key is cached by the verifier). */
    private boolean dekVerified(String deviceId) {
        Instant now = clock.instant();
        CachedVerdict c = dekCache.get(deviceId);
        if (c != null && c.at().plus(DEK_CACHE_TTL).isAfter(now)) {
            return c.verified();
        }
        boolean v = anchors.verify(deviceId);
        dekCache.put(deviceId, new CachedVerdict(now, v));
        return v;
    }

    private static double round2(double v) {
        return Math.round(v * 100.0) / 100.0;
    }

    /** Test hook: forget cached DEK verdicts (equivalent to waiting past the 30 s cache). */
    public void clearDekCache() {
        dekCache.clear();
    }
}
