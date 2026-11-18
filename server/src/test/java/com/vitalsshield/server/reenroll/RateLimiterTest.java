package com.vitalsshield.server.reenroll;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

/** DECISIONS #90: 10 per minute per address, 100 per minute globally, 429 with a Retry-After. */
class RateLimiterTest {

    final AtomicLong nanos = new AtomicLong(1_000_000_000L);
    final RateLimiter limiter = new RateLimiter(10, 100, Duration.ofMinutes(1), nanos::get);

    @Test
    void perAddressLimitThenRetryAfter() {
        for (int i = 0; i < 10; i++) {
            assertThat(limiter.tryAcquire("10.0.0.1").allowed()).as("request " + (i + 1)).isTrue();
        }
        RateLimiter.Decision d = limiter.tryAcquire("10.0.0.1");
        assertThat(d.allowed()).isFalse();
        // One token refills every 6 s at 10 per minute.
        assertThat(d.retryAfterSeconds()).isEqualTo(6);
        assertThat(limiter.tryAcquire("10.0.0.2").allowed()).as("another address").isTrue();

        nanos.addAndGet(Duration.ofSeconds(6).toNanos());
        assertThat(limiter.tryAcquire("10.0.0.1").allowed()).as("after the Retry-After").isTrue();
        assertThat(limiter.tryAcquire("10.0.0.1").allowed()).isFalse();
    }

    @Test
    void globalLimitAcrossAddresses() {
        for (int i = 0; i < 100; i++) {
            assertThat(limiter.tryAcquire("10.0.1." + (i / 10)).allowed()).as("request " + (i + 1)).isTrue();
        }
        RateLimiter.Decision d = limiter.tryAcquire("10.0.9.9");
        assertThat(d.allowed()).as("101st, fresh address").isFalse();
        assertThat(d.retryAfterSeconds()).isGreaterThanOrEqualTo(1);
        nanos.addAndGet(Duration.ofMillis(600).toNanos()); // 100 per minute: one token every 0.6 s
        assertThat(limiter.tryAcquire("10.0.9.9").allowed()).isTrue();
    }

    @Test
    void refusedRequestTakesNoToken() {
        for (int i = 0; i < 10; i++) {
            limiter.tryAcquire("10.0.0.1");
        }
        for (int i = 0; i < 50; i++) {
            limiter.tryAcquire("10.0.0.1"); // refused: must not drain the global bucket
        }
        for (int i = 0; i < 90; i++) {
            assertThat(limiter.tryAcquire("10.0.2." + (i / 10)).allowed()).as("global request " + (11 + i)).isTrue();
        }
    }
}
