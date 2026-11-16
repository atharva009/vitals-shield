package com.vitalsshield.devtools;

import com.vitalsshield.server.admin.webauthn.KmsRegistryAnchorKey;
import com.vitalsshield.server.admin.webauthn.RegistryAnchorKey;
import com.vitalsshield.server.kms.KmsKeyAdmin;
import com.vitalsshield.server.kms.KmsSigner;
import com.vitalsshield.server.pki.ActiveKmsKeys;
import java.net.URI;
import java.nio.file.Path;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * {@code ./gradlew :server:seedDemoDevice [--args="--device-id X --patient-id P --birth-year Y --auth webauthn|bearer"]}
 *
 * <p>webauthn (default): registers the software passkey in var/devseed/passkey.key on first use (KMS-anchored) and
 * provisions through the server's provisioning logic. bearer: the Phase 3 to 5 fake fields.
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
        JdbcTemplate jdbc = new JdbcTemplate(ds);
        TransactionTemplate tx = new TransactionTemplate(new DataSourceTransactionManager(ds));
        DevSeeder.Request request = new DevSeeder.Request(
                opts.getOrDefault("device-id", "dev_wearable_019"),
                opts.getOrDefault("patient-id", "demo-patient-001"),
                Integer.parseInt(opts.getOrDefault("birth-year", "1985")),
                Duration.parse(opts.getOrDefault("token-ttl", "PT1H")));
        String auth = opts.getOrDefault("auth", "webauthn");
        DevSeeder.Result r;
        if ("bearer".equals(auth)) {
            r = new DevSeeder(jdbc, tx, Clock.systemUTC()).seed(request);
        } else if ("webauthn".equals(auth)) {
            try (KmsClient kms = KmsClient.builder()
                    .httpClient(UrlConnectionHttpClient.builder().build())
                    .region(Region.of(opts.getOrDefault("kms-region", "us-east-1")))
                    .endpointOverride(URI.create(opts.getOrDefault("kms-endpoint", "http://localhost:4566")))
                    .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test")))
                    .build()) {
                RegistryAnchorKey anchor = new KmsRegistryAnchorKey(new KmsSigner(kms), new ActiveKmsKeys(jdbc),
                        new KmsKeyAdmin(kms));
                r = DevSeeder.seedWebAuthn(jdbc, tx, Clock.systemUTC(), anchor,
                        Path.of(opts.getOrDefault("passkey-file", "var/devseed/passkey.key")),
                        Integer.parseInt(opts.getOrDefault("admin-port", "8445")), request);
            }
        } else {
            throw new IllegalArgumentException("--auth must be webauthn or bearer, got " + auth);
        }
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
