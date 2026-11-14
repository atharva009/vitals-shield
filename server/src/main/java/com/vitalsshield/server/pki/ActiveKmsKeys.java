package com.vitalsshield.server.pki;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/** The ACTIVE kms_keys ARN for a purpose (DECISIONS #14). Blocking JDBC. */
@Repository
public class ActiveKmsKeys {

    private final JdbcTemplate jdbc;

    public ActiveKmsKeys(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public String requireArn(KeyPurpose purpose) {
        List<String> arns = jdbc.queryForList(
                "SELECT kms_key_id FROM kms_keys WHERE purpose = ?::kms_key_purpose AND status = 'ACTIVE'",
                String.class, purpose.name());
        if (arns.size() != 1) {
            throw new IllegalStateException("expected one ACTIVE " + purpose + " key, found " + arns.size());
        }
        return arns.get(0);
    }
}
