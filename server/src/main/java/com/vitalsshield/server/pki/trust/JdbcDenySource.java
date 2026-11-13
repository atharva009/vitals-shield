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
        return jdbc.query("""
                SELECT issuer_key_hash, serial_number, status::text AS status, revoked_at, grace_expires_at
                  FROM certificates
                 WHERE status IN ('REVOKED', 'EXPIRED', 'RENEWED')
                   AND not_after > NOW() - INTERVAL '1 day'
                """, (rs, i) -> new DenyRow(
                CertKey.of(rs.getString("issuer_key_hash"), rs.getString("serial_number")),
                rs.getString("status"),
                instant(rs.getTimestamp("revoked_at")),
                instant(rs.getTimestamp("grace_expires_at"))));
    }

    private static Instant instant(Timestamp ts) {
        return ts == null ? null : ts.toInstant();
    }
}
