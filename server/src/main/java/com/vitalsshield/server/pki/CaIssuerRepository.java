package com.vitalsshield.server.pki;

import java.util.List;
import java.util.Optional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/** Reads the current ACTIVE issuer for a purpose: ca_issuers.kms_primary_arn joined to kms_keys.kms_key_id. */
@Repository
public class CaIssuerRepository {

    private static final String ACTIVE_BY_PURPOSE = """
            SELECT k.purpose::text AS purpose, ci.issuer_key_hash, ci.subject_dn, ci.kms_primary_arn, ci.cert_pem
              FROM ca_issuers ci
              JOIN kms_keys k ON k.kms_key_id = ci.kms_primary_arn
             WHERE k.purpose = ?::kms_key_purpose
               AND k.status = 'ACTIVE'
               AND ci.status = 'ACTIVE'
            """;

    private final JdbcTemplate jdbc;

    public CaIssuerRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<CaIssuer> findActive(KeyPurpose purpose) {
        List<CaIssuer> rows = jdbc.query(ACTIVE_BY_PURPOSE, (rs, i) -> new CaIssuer(
                KeyPurpose.valueOf(rs.getString("purpose")),
                rs.getString("issuer_key_hash"),
                rs.getString("subject_dn"),
                rs.getString("kms_primary_arn"),
                rs.getString("cert_pem")), purpose.name());
        if (rows.size() > 1) {
            throw new IllegalStateException("more than one ACTIVE ca_issuers row for " + purpose);
        }
        return rows.stream().findFirst();
    }

    public CaIssuer requireActive(KeyPurpose purpose) {
        return findActive(purpose).orElseThrow(
                () -> new IllegalStateException("no ACTIVE ca_issuers row for " + purpose));
    }
}
