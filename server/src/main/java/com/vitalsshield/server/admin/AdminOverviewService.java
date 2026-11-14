package com.vitalsshield.server.admin;

import com.vitalsshield.server.boot.BootStatusTracker;
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
    /** Issuer of dev-seed tokens (DECISIONS #32, #51); the seed tool lives on the test classpath. */
    static final String DEV_SEED_CLINICIAN = "dev-seed-clinician";

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
    private final Map<String, CachedVerdict> dekCache = new ConcurrentHashMap<>();

    public AdminOverviewService(JdbcTemplate jdbc, BootStatusTracker boot, KmsHealthMonitor kms,
                                CaIssuerRepository issuers, CrlService crls, ActiveSessionRegistry sessions,
                                CertificateDenyList denyList, TelemetryMetrics telemetry, IssuedSerialLedger ledger,
                                SignerRevocationService revocations, QuarantineService quarantines,
                                DekAnchorVerifier anchors, Clock clock) {
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
        return out;
    }

    /** Newest first, at most {@code limit} rows. */
    public List<Map<String, Object>> telemetry(String deviceId, int limit) {
        return jdbc.query("""
                SELECT batch_id, sequence_number, measured_at, ingested_at, trust_state::text AS ts, heart_rate_bpm,
                       spo2_pct, hrv_rmssd_ms, perfusion_index
                  FROM telemetry_records WHERE device_id = ?
                 ORDER BY ingested_at DESC, sequence_number DESC LIMIT ?
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
                       (SELECT t.issued_by_clinician FROM device_bootstrap_tokens t WHERE t.device_id = d.device_id
                         ORDER BY t.expires_at DESC LIMIT 1) AS latest_token_issuer,
                       a.assignment_id::text AS assignment_id, a.patient_id, a.baseline_state::text AS baseline_state,
                       a.baseline_version,
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
            m.put("dev_seed", DEV_SEED_CLINICIAN.equals(rs.getString("latest_token_issuer")));
            m.put("dek_anchor_verified", rs.getBoolean("has_dek") ? dekVerified(id) : null);
            if (rs.getString("assignment_id") != null) {
                Map<String, Object> a = new LinkedHashMap<>();
                a.put("assignment_id", rs.getString("assignment_id"));
                a.put("patient_id", rs.getString("patient_id"));
                a.put("baseline_state", rs.getString("baseline_state"));
                a.put("baseline_version", rs.getInt("baseline_version"));
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
                m.put("active_cert", c);
            } else {
                m.put("active_cert", null);
            }
            m.put("live_sockets", liveByDevice.getOrDefault(id, 0));
            out.add(m);
        });
        return out;
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

    /** Test hook: forget cached DEK verdicts (equivalent to waiting past the 30 s cache). */
    public void clearDekCache() {
        dekCache.clear();
    }
}
