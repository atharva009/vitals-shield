package com.vitalsshield.simulator;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.crypto.EcKeys;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SimulatorStateStoreTest {

    // load() parses the certificate, so persistence tests use a throwaway self-signed one.
    static final String CERT_PEM = TestCert.PEM;

    @TempDir
    Path root;

    @Test
    void atomicWritesLeaveNoTempFiles() throws IOException {
        SimulatorStateStore store = new SimulatorStateStore(root, "dev_a");
        store.loadOrCreateDek();
        store.saveEnrollment(EcKeys.generateP256().getPrivate(), CERT_PEM, state(0));
        store.incrementSequence();

        try (Stream<Path> files = Files.walk(root)) {
            assertThat(files.filter(Files::isRegularFile).map(p -> p.getFileName().toString()))
                    .containsExactlyInAnyOrder("dek.key", "olk.key", "olk.crt", "state.json")
                    .noneMatch(n -> n.endsWith(".tmp"));
        }
    }

    @Test
    void keyFilesAreOwnerReadWriteOnly() throws IOException {
        Assumptions.assumeTrue(SimulatorStateStore.posix(), "not a POSIX file system");
        SimulatorStateStore store = new SimulatorStateStore(root, "dev_a");
        store.loadOrCreateDek();
        store.saveEnrollment(EcKeys.generateP256().getPrivate(), CERT_PEM, state(0));

        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(store.dekKeyFile())))
                .isEqualTo("rw-------");
        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(store.olkKeyFile())))
                .isEqualTo("rw-------");
    }

    @Test
    void resetStateKeepsDekAndRemovesState() throws IOException {
        SimulatorStateStore store = new SimulatorStateStore(root, "dev_a");
        store.loadOrCreateDek();
        byte[] dekBefore = Files.readAllBytes(store.dekKeyFile());
        store.saveEnrollment(EcKeys.generateP256().getPrivate(), CERT_PEM, state(0));

        store.resetState();

        assertThat(Files.readAllBytes(store.dekKeyFile())).isEqualTo(dekBefore);
        assertThat(store.deviceDir().resolve("state")).doesNotExist();
        assertThat(store.load()).isEmpty();
    }

    @Test
    void factoryWipeRemovesBoth() {
        SimulatorStateStore store = new SimulatorStateStore(root, "dev_a");
        store.loadOrCreateDek();
        store.saveEnrollment(EcKeys.generateP256().getPrivate(), CERT_PEM, state(0));

        store.factoryWipe();

        assertThat(store.deviceDir().resolve("keys")).doesNotExist();
        assertThat(store.deviceDir().resolve("state")).doesNotExist();
    }

    @Test
    void loadSaveRoundTrip() {
        SimulatorStateStore store = new SimulatorStateStore(root, "dev_a");
        KeyPair olk = EcKeys.generateP256();
        SimulatorState s = state(7);
        store.saveEnrollment(olk.getPrivate(), CERT_PEM, s);

        SimulatorStateStore.Enrollment loaded = new SimulatorStateStore(root, "dev_a").load().orElseThrow();

        assertThat(loaded.state()).isEqualTo(s);
        assertThat(loaded.olkKey().getEncoded()).isEqualTo(olk.getPrivate().getEncoded());
        assertThat(loaded.olkCert()).isEqualTo(SimulatorStateStore.parseCert(CERT_PEM));
    }

    @Test
    void incrementSequenceIsPersistedBeforeUse() {
        SimulatorStateStore store = new SimulatorStateStore(root, "dev_a");
        store.saveEnrollment(EcKeys.generateP256().getPrivate(), CERT_PEM, state(0));

        assertThat(store.incrementSequence()).isEqualTo(1);
        assertThat(store.incrementSequence()).isEqualTo(2);
        assertThat(new SimulatorStateStore(root, "dev_a").load().orElseThrow().state().sequenceNumber())
                .isEqualTo(2);
    }

    @Test
    void reloadedDekHasTheSamePublicKey() {
        SimulatorStateStore store = new SimulatorStateStore(root, "dev_a");
        KeyPair created = store.loadOrCreateDek();
        KeyPair reloaded = new SimulatorStateStore(root, "dev_a").loadOrCreateDek();

        assertThat(reloaded.getPublic().getEncoded()).isEqualTo(created.getPublic().getEncoded());
        assertThat(reloaded.getPrivate().getEncoded()).isEqualTo(created.getPrivate().getEncoded());
    }

    static SimulatorState state(long seq) {
        return new SimulatorState("dev_a", 1, seq, "00000000-0000-0000-0000-000000000001",
                "2026-11-13T12:00:00Z", "2026-11-13T12:00:01Z");
    }

    @Test
    void nextBatchPersistsSequenceAndMeasuredAtTogether() {
        SimulatorStateStore store = new SimulatorStateStore(root, "dev_x");
        store.saveEnrollment(com.vitalsshield.crypto.EcKeys.generateP256().getPrivate(), TestCert.PEM,
                new SimulatorState("dev_x", 1, 0, "a", "f", "e"));
        java.time.Instant now = java.time.Instant.parse("2026-11-16T12:00:00Z");
        SimulatorStateStore.NextBatch first = store.nextBatch(now);
        assertThat(first.sequenceNumber()).isEqualTo(1);
        assertThat(first.measuredAt()).isEqualTo(now.minus(java.time.Duration.ofHours(12)));
        SimulatorStateStore.NextBatch second = store.nextBatch(now.plusSeconds(1));
        assertThat(second.sequenceNumber()).isEqualTo(2);
        assertThat(second.measuredAt()).isEqualTo(first.measuredAt().plusSeconds(60));
        // A fresh store instance (a restart) continues from the persisted value, not from now - 12 h.
        SimulatorStateStore reopened = new SimulatorStateStore(root, "dev_x");
        assertThat(reopened.nextBatch(now.plusSeconds(2)).measuredAt()).isEqualTo(first.measuredAt().plusSeconds(120));
    }

    @Test
    void scenarioFileRoundTrip() {
        SimulatorStateStore store = new SimulatorStateStore(root, "dev_y");
        assertThat(store.readScenario()).isEmpty();
        store.writeScenario(Scenario.LOW_PERFUSION_CRITICAL);
        assertThat(store.readScenario()).contains(Scenario.LOW_PERFUSION_CRITICAL);
    }
}
