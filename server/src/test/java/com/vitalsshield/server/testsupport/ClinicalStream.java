package com.vitalsshield.server.testsupport;

import com.vitalsshield.simulator.Scenario;
import com.vitalsshield.simulator.TelemetryFrames;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.UUID;

/**
 * Drives the real ingest endpoint over one mTLS connection with the simulator's scenario generators and a fixed
 * compressed clock: batch n is measured at {@code start + n * step}. Every batch must be answered 200.
 */
public final class ClinicalStream implements AutoCloseable {

    public record Sent(UUID batchId, long seq, Instant measuredAt, TelemetryFrames.Metrics metrics, String trustState) {
    }

    private final SpineFixture.Device device;
    private final MtlsTestClient.Connection conn;
    private final Duration step;
    private final List<Sent> sent = new ArrayList<>();
    private long seq;
    private Instant next;

    public ClinicalStream(SpineFixture fx, SpineFixture.Device device, X509Certificate root, Instant start,
                          Duration step) {
        this.device = device;
        this.step = step;
        this.next = start;
        try {
            this.conn = fx.connect(device, root);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public Sent send(Scenario s) {
        return send(s.generate(new Random(device.deviceId().hashCode() * 31L + seq + 1)));
    }

    public List<Sent> send(Scenario s, int n) {
        List<Sent> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(send(s));
        }
        return out;
    }

    public Sent send(TelemetryFrames.Metrics m) {
        seq++;
        UUID batchId = UUID.randomUUID();
        Instant measuredAt = next;
        next = next.plus(step);
        String jws = SpineFixture.frame(device, seq, batchId, measuredAt, m, device.assignmentId(), device.bootEpoch());
        try {
            MtlsTestClient.Response r = SpineFixture.ingest(conn, jws);
            if (r.status() != 200) {
                throw new IllegalStateException("ingest " + r.status() + " " + r.body());
            }
            String ts = r.body().replaceAll(".*\"trust_state\":\"([A-Z_]+)\".*", "$1");
            Sent s = new Sent(batchId, seq, measuredAt, m, ts);
            sent.add(s);
            return s;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public List<Sent> sent() {
        return sent;
    }

    public Instant nextMeasuredAt() {
        return next;
    }

    /** Moves the measured clock (sequence numbers keep counting). */
    public void measureNextAt(Instant at) {
        next = at;
    }

    @Override
    public void close() throws IOException {
        conn.close();
    }
}
