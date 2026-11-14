package com.vitalsshield.server.testsupport;

import org.springframework.jdbc.core.JdbcTemplate;

/** DECISIONS #38: every certificates row has an issued_serials row, and none is left RESERVED. */
public final class LedgerInvariant {

    /** The same query the dashboard runs (single source of truth in main code). */
    public static final String VIOLATIONS_SQL = com.vitalsshield.server.pki.IssuedSerialLedger.INVARIANT_SQL;

    private LedgerInvariant() {
    }

    public static int violations(JdbcTemplate jdbc) {
        return jdbc.queryForObject(VIOLATIONS_SQL, Integer.class);
    }
}
