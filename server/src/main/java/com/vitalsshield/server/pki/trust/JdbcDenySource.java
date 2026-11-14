package com.vitalsshield.server.pki.trust;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Certificates that must be denied. Rows whose not_after is more than a day in the past are skipped: they already fail
 * the PKIX validity check. Blocking; callers run it on boundedElastic or the boot thread.
 */
@Component
public class JdbcDenySource implements DenySource {

    private final JdbcTemplate jdbc;

    public JdbcDenySource(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public List<DenyRow> load() {
        List<DenyRow> rows = new java.util.ArrayList<>(jdbc.query("""
                SELECT issuer_key_hash, serial_number, status::text AS status, revoked_at, grace_expires_at
                  FROM certificates
                 WHERE status IN ('REVOKED', 'EXPIRED', 'RENEWED')
                   AND not_after > NOW() - INTERVAL '1 day'
                """, (rs, i) -> new DenyRow(
                CertKey.of(rs.getString("issuer_key_hash"), rs.getString("serial_number")),
                rs.getString("status"),
                instant(rs.getTimestamp("revoked_at")),
                instant(rs.getTimestamp("grace_expires_at")))));
        return addVoidedSerials(rows);
    }

    /** VOIDED ledger serials (DECISIONS #38): signed or possibly signed, never activated; denied from voided_at. */
    private List<DenyRow> addVoidedSerials(List<DenyRow> rows) {
        rows.addAll(jdbc.query("""
                SELECT issuer_key_hash, serial_number, voided_at FROM issued_serials
                 WHERE status = 'VOIDED' AND reserved_at > NOW() - INTERVAL '2 days'
                """, (rs, i) -> new DenyRow(
                CertKey.of(rs.getString("issuer_key_hash"), rs.getString("serial_number")),
                "VOIDED", instant(rs.getTimestamp("voided_at")), null)));
        return rows;
    }

    private static Instant instant(Timestamp ts) {
        return ts == null ? null : ts.toInstant();
    }
}
