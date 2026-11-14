package com.vitalsshield.server.testsupport;

import org.springframework.jdbc.core.JdbcTemplate;

/** DECISIONS #38: every certificates row has an issued_serials row, and none is left RESERVED. */
public final class LedgerInvariant {

    public static final String VIOLATIONS_SQL = """
            SELECT count(*) FROM certificates c
              LEFT JOIN issued_serials s USING (issuer_key_hash, serial_number)
             WHERE s.serial_number IS NULL OR s.status = 'RESERVED'
            """;

    private LedgerInvariant() {
    }

    public static int violations(JdbcTemplate jdbc) {
        return jdbc.queryForObject(VIOLATIONS_SQL, Integer.class);
    }
}
