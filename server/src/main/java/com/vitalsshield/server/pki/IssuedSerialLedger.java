package com.vitalsshield.server.pki;

import com.vitalsshield.server.pki.trust.CertKey;
import java.math.BigInteger;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * The issued_serials ledger (DECISIONS #38). RESERVED before any KMS call, RECORDED when the certificate row is
 * activated, VOIDED when an activation aborts or a reservation goes stale. Every method runs inside the caller's
 * transaction (blocking JDBC).
 */
@Repository
public class IssuedSerialLedger {

    /** A RESERVED serial older than this was never activated (crash, lost race) and is voided by the sweep. */
    public static final Duration STALE_AFTER = Duration.ofMinutes(2);
    static final int MAX_RESERVE_ATTEMPTS = 3;

    private final JdbcTemplate jdbc;
    private final SerialAllocator allocator;

    public IssuedSerialLedger(JdbcTemplate jdbc, SerialAllocator allocator) {
        this.jdbc = jdbc;
        this.allocator = allocator;
    }

    /**
     * Allocates and reserves a serial under {@code issuerKeyHash}. A primary-key collision (astronomically unlikely)
     * is retried with a new serial, at most 3 times. ON CONFLICT DO NOTHING keeps the surrounding transaction alive.
     */
    public BigInteger reserve(String issuerKeyHash, String deviceId) {
        for (int attempt = 0; attempt < MAX_RESERVE_ATTEMPTS; attempt++) {
            BigInteger serial = allocator.next();
            int inserted = jdbc.update("""
                    INSERT INTO issued_serials (issuer_key_hash, serial_number, device_id, status)
                    VALUES (?, ?, ?, 'RESERVED')
                    ON CONFLICT (issuer_key_hash, serial_number) DO NOTHING
                    """, issuerKeyHash, SerialNumbers.toHex(serial), deviceId);
            if (inserted == 1) {
                return serial;
            }
        }
        throw new IllegalStateException("could not reserve a unique serial after " + MAX_RESERVE_ATTEMPTS + " attempts");
    }

    /** RESERVED to RECORDED. Returns false if the reservation is gone (voided by the sweep). */
    public boolean record(CertKey key) {
        return jdbc.update("""
                UPDATE issued_serials SET status = 'RECORDED'
                 WHERE issuer_key_hash = ? AND serial_number = ? AND status = 'RESERVED'
                """, key.issuerKeyHash(), key.serial()) == 1;
    }

    /**
     * Marks {@code key} VOIDED, creating the row if it does not exist (for example a leaf that was signed under a
     * different issuer than the one reserved during a rebuild race). Never downgrades RECORDED.
     */
    public void voidSerial(CertKey key, String deviceId, Instant voidedAt) {
        jdbc.update("""
                INSERT INTO issued_serials (issuer_key_hash, serial_number, device_id, status, voided_at)
                VALUES (?, ?, ?, 'VOIDED', ?)
                ON CONFLICT (issuer_key_hash, serial_number) DO UPDATE
                   SET status = 'VOIDED', voided_at = EXCLUDED.voided_at
                 WHERE issued_serials.status = 'RESERVED'
                """, key.issuerKeyHash(), key.serial(), deviceId, Timestamp.from(voidedAt));
    }

    /** Voids every RESERVED serial older than 2 minutes; returns what it voided (for the deny-list). */
    public List<CertKey> sweepStale() {
        return jdbc.query("""
                UPDATE issued_serials SET status = 'VOIDED', voided_at = NOW()
                 WHERE status = 'RESERVED' AND reserved_at < NOW() - INTERVAL '2 minutes'
                RETURNING issuer_key_hash, serial_number
                """, (rs, i) -> CertKey.of(rs.getString("issuer_key_hash"), rs.getString("serial_number")));
    }

    /** Hierarchy rebuild: every RESERVED serial belongs to an issuer that is about to be revoked. */
    public int voidAllReserved() {
        return jdbc.update("UPDATE issued_serials SET status = 'VOIDED', voided_at = NOW() WHERE status = 'RESERVED'");
    }

    /** DECISIONS #38 invariant: certificates rows without a ledger row, or whose ledger row is still RESERVED. */
    public static final String INVARIANT_SQL = """
            SELECT count(*) FROM certificates c
              LEFT JOIN issued_serials s USING (issuer_key_hash, serial_number)
             WHERE s.serial_number IS NULL OR s.status = 'RESERVED'
            """;

    public int invariantViolations() {
        return jdbc.queryForObject(INVARIANT_SQL, Integer.class);
    }

    /** Ledger row counts by status. */
    public java.util.Map<String, Long> countsByStatus() {
        java.util.Map<String, Long> out = new java.util.TreeMap<>(java.util.Map.of("RECORDED", 0L, "VOIDED", 0L,
                "RESERVED", 0L));
        jdbc.query("SELECT status::text, count(*) FROM issued_serials GROUP BY 1",
                rs -> {
                    out.put(rs.getString(1), rs.getLong(2));
                });
        return out;
    }

    /** Pure helper for the sweep rule, so the boundary can be unit-tested: stale iff reservedAt < now - 2 min. */
    public static boolean isStale(Instant reservedAt, Instant now) {
        return reservedAt.isBefore(now.minus(STALE_AFTER));
    }
}
