package com.vitalsshield.server.pki.trust;

import java.util.List;

/** Loads deny-list candidates. JDBC in production ({@link JdbcDenySource}), a list in unit tests. */
@FunctionalInterface
public interface DenySource {

    List<DenyRow> load();
}
