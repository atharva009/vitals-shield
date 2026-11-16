package com.vitalsshield.server.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/**
 * Hash-chained {@code security_audit_log} (spec Section 7, DECISIONS #62). {@link #append} must run inside the
 * caller's transaction: it takes {@code pg_advisory_xact_lock}, reads the latest entry_hash ("0" x 64 for the first
 * entry), and inserts
 * {@code entry_hash = hex(SHA-256(prev_hash || canonical_json({event_type, actor_id, payload}) || created_at))}.
 * Canonical JSON: keys sorted, no whitespace; payload values are strings, integers, booleans, or nested maps.
 * S3 Object Lock anchoring of the chain head stays "Designed".
 */
@Component
public class AuditLog {

    public static final long LOCK_KEY = 0x5653_4155_4449_54L; // "VSAUDIT"
    public static final String GENESIS = "0".repeat(64);
    private static final JsonMapper JSON = JsonMapper.builder().build();

    public record Entry(long sequenceId, String eventType, String actorId, Map<String, Object> payload,
                        String prevHash, String entryHash, Instant createdAt) {
    }

    /** {@code firstBrokenSequenceId} is null when the chain is valid. */
    public record Verification(boolean valid, Long firstBrokenSequenceId, int entries) {
    }

    private final JdbcTemplate jdbc;
    private final Clock clock;

    public AuditLog(JdbcTemplate jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    /**
     * Inside the caller's transaction, as its LAST statement. Returns the new entry hash.
     *
     * <p>Lock ordering rule (DECISIONS #67): every transaction that appends here takes this advisory lock last, after
     * all the row locks it needs (devices FOR UPDATE, token and assignment updates, the sanitize CTE, FK key-share
     * locks from inserts). A transaction holding the advisory lock therefore never waits for a row lock, so no cycle
     * "A holds a row and waits for the audit lock, B holds the audit lock and waits for that row" can form. Callers:
     * WebAuthnService.registerFinish, ProvisioningService.begin/finish/closeAssignment, StepUpService.restore,
     * QuarantineService.sanitize. Each appends after its last row-locking statement.
     */
    public String append(String eventType, String actorId, Map<String, Object> payload) {
        jdbc.queryForList("SELECT pg_advisory_xact_lock(?)", LOCK_KEY);
        List<String> last = jdbc.queryForList(
                "SELECT entry_hash FROM security_audit_log ORDER BY sequence_id DESC LIMIT 1", String.class);
        String prev = last.isEmpty() ? GENESIS : last.get(0);
        Instant createdAt = clock.instant().truncatedTo(ChronoUnit.MICROS); // timestamptz precision
        String payloadJson = canonical(payload);
        String hash = entryHash(prev, eventType, actorId, payload, createdAt);
        jdbc.update("""
                INSERT INTO security_audit_log (event_type, actor_id, payload_json, prev_entry_hash, entry_hash, created_at)
                VALUES (?, ?, ?::jsonb, ?, ?, ?)
                """, eventType, actorId, payloadJson, prev, hash, Timestamp.from(createdAt));
        return hash;
    }

    public List<Entry> latest(int limit) {
        return query("ORDER BY sequence_id DESC LIMIT " + Math.max(1, Math.min(limit, 500)));
    }

    /** Recomputes every hash in sequence order. */
    public Verification verify() {
        List<Entry> all = query("ORDER BY sequence_id ASC");
        String prev = GENESIS;
        for (Entry e : all) {
            String expected = entryHash(prev, e.eventType(), e.actorId(), e.payload(), e.createdAt());
            if (!e.prevHash().equals(prev) || !e.entryHash().equals(expected)) {
                return new Verification(false, e.sequenceId(), all.size());
            }
            prev = e.entryHash();
        }
        return new Verification(true, null, all.size());
    }

    static String entryHash(String prev, String eventType, String actorId, Map<String, Object> payload,
                            Instant createdAt) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("event_type", eventType);
        fields.put("actor_id", actorId);
        fields.put("payload", payload);
        return sha256Hex(prev + canonical(fields) + createdAt.toString());
    }

    private List<Entry> query(String suffix) {
        List<Entry> out = new ArrayList<>();
        jdbc.query("SELECT sequence_id, event_type, actor_id, payload_json::text, prev_entry_hash, entry_hash, created_at "
                + "FROM security_audit_log " + suffix, rs -> {
            out.add(new Entry(rs.getLong(1), rs.getString(2), rs.getString(3), parse(rs.getString(4)),
                    rs.getString(5), rs.getString(6), rs.getTimestamp(7).toInstant()));
        });
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parse(String json) {
        return JSON.readValue(json, Map.class);
    }

    /** Sorted keys, no whitespace. Only maps, strings, numbers, booleans, and null are expected. */
    @SuppressWarnings("unchecked")
    static String canonical(Object value) {
        if (value instanceof Map<?, ?> m) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, Object> e : new TreeMap<>((Map<String, Object>) m).entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append(JSON.writeValueAsString(e.getKey())).append(':').append(canonical(e.getValue()));
            }
            return sb.append('}').toString();
        }
        return JSON.writeValueAsString(value);
    }

    private static String sha256Hex(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
