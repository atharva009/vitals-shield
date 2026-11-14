package com.vitalsshield.devtools;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * {@code ./gradlew :server:seedDemoDevice [--args="--device-id X --patient-id P --birth-year Y --token-ttl PT1H"]}
 *
 * <p>Dev only (DECISIONS #32): runs from the test classpath, never an HTTP endpoint, and refuses any database other
 * than the local Compose Postgres (localhost or 127.0.0.1, port 5433). Prints the bootstrap token once.
 */
public final class SeedDemoDevice {

    static final String DEFAULT_URL = "jdbc:postgresql://localhost:5433/vitalsshield";

    private SeedDemoDevice() {
    }

    public static void main(String[] args) {
        Map<String, String> opts = new HashMap<>();
        for (int i = 0; i + 1 < args.length; i += 2) {
            if (!args[i].startsWith("--")) {
                throw new IllegalArgumentException("expected --name value, got " + args[i]);
            }
            opts.put(args[i].substring(2), args[i + 1]);
        }
        String url = opts.getOrDefault("jdbc-url", DEFAULT_URL);
        requireLocalCompose(url);

        DriverManagerDataSource ds = new DriverManagerDataSource(url,
                opts.getOrDefault("db-user", "vitalsshield"), opts.getOrDefault("db-password", "vitalsshield"));
        DevSeeder seeder = new DevSeeder(new JdbcTemplate(ds),
                new TransactionTemplate(new DataSourceTransactionManager(ds)), Clock.systemUTC());
        DevSeeder.Result r = seeder.seed(new DevSeeder.Request(
                opts.getOrDefault("device-id", "dev_wearable_019"),
                opts.getOrDefault("patient-id", "demo-patient-001"),
                Integer.parseInt(opts.getOrDefault("birth-year", "1985")),
                Duration.parse(opts.getOrDefault("token-ttl", "PT1H"))));
        System.out.println("BOOTSTRAP_TOKEN=" + r.token());
    }

    /** Throws unless the JDBC URL points at the local Compose database. */
    static void requireLocalCompose(String jdbcUrl) {
        if (!jdbcUrl.startsWith("jdbc:postgresql://")) {
            throw new IllegalStateException("refusing to seed: not a PostgreSQL JDBC URL: " + jdbcUrl);
        }
        URI uri = URI.create(jdbcUrl.substring("jdbc:".length()));
        boolean localHost = "localhost".equals(uri.getHost()) || "127.0.0.1".equals(uri.getHost());
        if (!localHost || uri.getPort() != 5433) {
            throw new IllegalStateException(
                    "refusing to seed: only the local Compose database (localhost:5433) is allowed, got " + jdbcUrl);
        }
    }
}
