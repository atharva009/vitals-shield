package com.vitalsshield.server.telemetry;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.telemetry.ReplayWindowModel.Decision;
import com.vitalsshield.server.testsupport.MtlsTestClient;
import com.vitalsshield.server.testsupport.SpineFixture;
import com.vitalsshield.server.testsupport.TestPorts;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * 2000 random operations against one device, each applied to {@link ReplayWindowModel} and to the real endpoint.
 * Decisions must match at every step, and the final window must match the devices row. Set -Dreplay.seed to replay.
 */
@Tag("integration")
@Testcontainers
@ActiveProfiles("local")
@SpringBootTest
class ReplayWindowPropertyIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    static TestPorts.Listeners ports;
    static Path trustFile;
    static Path stateRoot;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) throws IOException {
        Path dir = Files.createTempDirectory("vs-replay-it");
        trustFile = dir.resolve("root-ca.pem");
        stateRoot = dir.resolve("sim");
        registry.add("vitalsshield.pki.trust-file", trustFile::toString);
        ports = TestPorts.register(registry);
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired TrustAnchors anchors;

    enum Op { IN_ORDER, OUT_OF_ORDER, GAP_64, GAP_65, RESEND_IDENTICAL, DUPLICATE_NEW_BATCH, TOO_OLD_64, TOO_OLD_65 }

    enum Outcome { ACCEPT, IDEMPOTENT, DUPLICATE, TOO_OLD }

    @Test
    void endpointMatchesModel() throws Exception {
        long seed = Long.getLong("replay.seed", System.nanoTime());
        System.out.println("REPLAY_PROPERTY_SEED=" + seed);
        Random rnd = new Random(seed);
        SpineFixture fx = new SpineFixture(jdbc, tx, ports, trustFile, stateRoot);
        SpineFixture.Device d = fx.enroll("dev_replay_prop");
        ReplayWindowModel model = new ReplayWindowModel();
        Map<Long, String> acceptedFrames = new HashMap<>();
        List<Long> acceptedSeqs = new ArrayList<>();
        Map<Op, Integer> counts = new java.util.EnumMap<>(Op.class);

        try (MtlsTestClient.Connection c = fx.connect(d, anchors.root())) {
            for (int i = 0; i < 2000; i++) {
                Op op = pick(rnd, model, acceptedSeqs);
                counts.merge(op, 1, Integer::sum);
                long seq;
                String jws;
                Outcome expected;
                if (op == Op.RESEND_IDENTICAL) {
                    seq = acceptedSeqs.get(rnd.nextInt(acceptedSeqs.size()));
                    jws = acceptedFrames.get(seq);
                    expected = Outcome.IDEMPOTENT;
                } else {
                    seq = switch (op) {
                        case IN_ORDER -> model.last + 1;
                        case OUT_OF_ORDER -> model.last - 1 - rnd.nextInt((int) Math.min(63, model.last - 1));
                        case GAP_64 -> model.last + 64;
                        case GAP_65 -> model.last + 65;
                        case DUPLICATE_NEW_BATCH -> acceptedSeqs.get(rnd.nextInt(acceptedSeqs.size()));
                        case TOO_OLD_64 -> model.last - 64;
                        case TOO_OLD_65 -> model.last - 65;
                        default -> throw new IllegalStateException();
                    };
                    jws = SpineFixture.frame(d, seq, UUID.randomUUID());
                    Decision decision = model.offer(seq);
                    expected = switch (decision) {
                        case ACCEPT -> Outcome.ACCEPT;
                        case DUPLICATE -> Outcome.DUPLICATE;
                        case TOO_OLD -> Outcome.TOO_OLD;
                    };
                }

                MtlsTestClient.Response r = SpineFixture.ingest(c, jws);
                Outcome actual = outcome(r);
                assertThat(actual)
                        .as("seed=%d op#%d %s seq=%d (model last=%d) response=%d %s", seed, i, op, seq, model.last,
                                r.status(), r.body())
                        .isEqualTo(expected);
                if (expected == Outcome.ACCEPT) {
                    acceptedFrames.put(seq, jws);
                    acceptedSeqs.add(seq);
                }
            }
        }

        Map<String, Object> device = jdbc.queryForMap(
                "SELECT last_sequence_num, replay_bitmap FROM devices WHERE device_id = 'dev_replay_prop'");
        System.out.println("REPLAY_PROPERTY_OPS=" + counts + " final last=" + model.last
                + " bitmap=" + Long.toHexString(model.bitmap));
        assertThat(device.get("last_sequence_num")).as("seed=%d", seed).isEqualTo(model.last);
        assertThat(device.get("replay_bitmap")).as("seed=%d", seed).isEqualTo(model.bitmap);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM telemetry_records WHERE device_id = 'dev_replay_prop'",
                Integer.class)).isEqualTo(acceptedSeqs.size());
    }

    private static Op pick(Random rnd, ReplayWindowModel m, List<Long> accepted) {
        while (true) {
            int roll = rnd.nextInt(100);
            Op op = roll < 35 ? Op.IN_ORDER : roll < 60 ? Op.OUT_OF_ORDER : roll < 65 ? Op.GAP_64
                    : roll < 70 ? Op.GAP_65 : roll < 80 ? Op.RESEND_IDENTICAL : roll < 90 ? Op.DUPLICATE_NEW_BATCH
                    : roll < 95 ? Op.TOO_OLD_64 : Op.TOO_OLD_65;
            boolean ok = switch (op) {
                case OUT_OF_ORDER -> m.last >= 2;
                case RESEND_IDENTICAL, DUPLICATE_NEW_BATCH -> !accepted.isEmpty();
                case TOO_OLD_64 -> m.last - 64 >= 1;
                case TOO_OLD_65 -> m.last - 65 >= 1;
                default -> true;
            };
            if (ok) {
                return op;
            }
        }
    }

    private static Outcome outcome(MtlsTestClient.Response r) {
        if (r.status() == 200) {
            return r.body().contains("\"idempotent_retry\":true") ? Outcome.IDEMPOTENT : Outcome.ACCEPT;
        }
        if (r.status() == 409 && r.body().contains("DUPLICATE_SEQUENCE_REPLAY")) {
            return Outcome.DUPLICATE;
        }
        if (r.status() == 409 && r.body().contains("SEQUENCE_TOO_OLD")) {
            return Outcome.TOO_OLD;
        }
        throw new AssertionError("unexpected response " + r.status() + " " + r.body());
    }
}
