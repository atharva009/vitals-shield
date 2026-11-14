package com.vitalsshield.server.admin;

import java.util.List;

/** The ACTIVE kms_keys rows (purpose, ARN). JDBC in production, a list in unit tests. */
@FunctionalInterface
public interface ActiveKeySource {

    record ActiveKey(String purpose, String arn) {
    }

    List<ActiveKey> load();
}
