package com.vitalsshield.server.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.vitalsshield.server.kms.KmsKeyAdmin;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.exception.SdkClientException;

class KmsHealthMonitorTest {

    static final List<ActiveKeySource.ActiveKey> FOUR = List.of(
            new ActiveKeySource.ActiveKey("DEVICE_INTERMEDIATE", "arn:aws:kms:us-east-1:000000000000:key/aaaa-0001"),
            new ActiveKeySource.ActiveKey("REGISTRY_ANCHOR", "arn:aws:kms:us-east-1:000000000000:key/aaaa-0002"),
            new ActiveKeySource.ActiveKey("ROOT_CA", "arn:aws:kms:us-east-1:000000000000:key/aaaa-0003"),
            new ActiveKeySource.ActiveKey("SERVER_TLS_CA", "arn:aws:kms:us-east-1:000000000000:key/aaaa-0004"));

    final KmsKeyAdmin admin = mock(KmsKeyAdmin.class);
    final KmsHealthMonitor monitor = new KmsHealthMonitor(() -> FOUR, admin, Clock.systemUTC());

    @Test
    void allEnabledIsHealthy() {
        when(admin.describeEnabled(anyString())).thenReturn(true);

        KmsHealthMonitor.Snapshot s = monitor.checkNow();

        assertThat(s.state()).isEqualTo(KmsHealthMonitor.State.HEALTHY);
        assertThat(s.healthy()).isTrue();
        assertThat(s.keys()).hasSize(4).allSatisfy(k -> assertThat(k.enabled()).isTrue());
        assertThat(s.keys().get(0).arnSuffix()).isEqualTo("ey/aaaa-0001");
    }

    @Test
    void oneMissingIsUnhealthy() {
        when(admin.describeEnabled(anyString())).thenReturn(true);
        when(admin.describeEnabled(FOUR.get(1).arn())).thenReturn(false);

        KmsHealthMonitor.Snapshot s = monitor.checkNow();

        assertThat(s.state()).isEqualTo(KmsHealthMonitor.State.UNHEALTHY);
        assertThat(s.keys()).filteredOn(k -> "REGISTRY_ANCHOR".equals(k.purpose()))
                .singleElement().satisfies(k -> assertThat(k.enabled()).isFalse());
    }

    @Test
    void networkErrorIsUnknownNotMissing() {
        when(admin.describeEnabled(anyString())).thenReturn(true);
        when(admin.describeEnabled(FOUR.get(2).arn())).thenThrow(SdkClientException.create("connection refused"));

        KmsHealthMonitor.Snapshot s = monitor.checkNow();

        assertThat(s.state()).isEqualTo(KmsHealthMonitor.State.UNKNOWN);
        assertThat(s.keys()).filteredOn(k -> "ROOT_CA".equals(k.purpose())).singleElement().satisfies(k -> {
            assertThat(k.enabled()).isNull();
            assertThat(k.error()).isEqualTo("SdkClientException");
        });
    }

    @Test
    void recoversToHealthy() {
        when(admin.describeEnabled(anyString())).thenReturn(false);
        assertThat(monitor.checkNow().state()).isEqualTo(KmsHealthMonitor.State.UNHEALTHY);

        when(admin.describeEnabled(anyString())).thenReturn(true);
        assertThat(monitor.checkNow().state()).isEqualTo(KmsHealthMonitor.State.HEALTHY);
    }

    @Test
    void fewerThanFourActiveKeysIsUnhealthy() {
        KmsHealthMonitor partial = new KmsHealthMonitor(() -> FOUR.subList(0, 3), admin, Clock.systemUTC());
        when(admin.describeEnabled(anyString())).thenReturn(true);
        assertThat(partial.checkNow().state()).isEqualTo(KmsHealthMonitor.State.UNHEALTHY);
    }
}
