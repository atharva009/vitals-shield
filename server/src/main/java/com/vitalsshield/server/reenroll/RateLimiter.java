package com.vitalsshield.server.reenroll;

import java.time.Duration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.function.LongSupplier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * In-memory token buckets for GET /api/v1/devices/challenge (DECISIONS #90): one per remote address and one global.
 * Each bucket holds {@code limit} tokens and refills continuously at {@code limit} per {@code window}. A request
 * takes one token from both buckets or from neither. On refusal, {@code retryAfterSeconds} is when the scarcer bucket
 * next has a token (at least 1).
 *
 * <p>Per process only: several gateways would each allow the limit (Redis stays "Designed").
 */
@Component
public class RateLimiter {

    public record Decision(boolean allowed, long retryAfterSeconds) {
    }

    static final class Bucket {
        double tokens;
        long lastNanos;

        Bucket(double tokens, long lastNanos) {
            this.tokens = tokens;
            this.lastNanos = lastNanos;
        }
    }

    /** Address buckets are dropped once full again, so the map stays small. */
    static final int PRUNE_AT = 10_000;

    private final int perAddress;
    private final int global;
    private final double perNanoAddress;
    private final double perNanoGlobal;
    private final LongSupplier nanos;
    private final Map<String, Bucket> addresses = new HashMap<>();
    private final Bucket globalBucket;

    @Autowired
    public RateLimiter(ReEnrollProperties props) {
        this(props.perAddressLimit(), props.globalLimit(), props.rateWindow(), System::nanoTime);
    }

    RateLimiter(int perAddress, int global, Duration window, LongSupplier nanos) {
        this.perAddress = perAddress;
        this.global = global;
        this.perNanoAddress = perAddress / (double) window.toNanos();
        this.perNanoGlobal = global / (double) window.toNanos();
        this.nanos = nanos;
        this.globalBucket = new Bucket(global, nanos.getAsLong());
    }

    public synchronized Decision tryAcquire(String address) {
        long now = nanos.getAsLong();
        refill(globalBucket, now, global, perNanoGlobal);
        Bucket a = addresses.computeIfAbsent(address == null ? "unknown" : address, k -> new Bucket(perAddress, now));
        refill(a, now, perAddress, perNanoAddress);
        if (a.tokens >= 1 && globalBucket.tokens >= 1) {
            a.tokens -= 1;
            globalBucket.tokens -= 1;
            if (addresses.size() > PRUNE_AT) {
                prune(now);
            }
            return new Decision(true, 0);
        }
        double waitAddress = a.tokens >= 1 ? 0 : (1 - a.tokens) / perNanoAddress;
        double waitGlobal = globalBucket.tokens >= 1 ? 0 : (1 - globalBucket.tokens) / perNanoGlobal;
        long seconds = (long) Math.ceil(Math.max(waitAddress, waitGlobal) / 1e9);
        return new Decision(false, Math.max(1, seconds));
    }

    private static void refill(Bucket b, long now, int limit, double perNano) {
        long elapsed = now - b.lastNanos;
        if (elapsed > 0) {
            b.tokens = Math.min(limit, b.tokens + elapsed * perNano);
            b.lastNanos = now;
        }
    }

    private void prune(long now) {
        for (Iterator<Bucket> it = addresses.values().iterator(); it.hasNext(); ) {
            Bucket b = it.next();
            refill(b, now, perAddress, perNanoAddress);
            if (b.tokens >= perAddress) {
                it.remove();
            }
        }
    }
}
