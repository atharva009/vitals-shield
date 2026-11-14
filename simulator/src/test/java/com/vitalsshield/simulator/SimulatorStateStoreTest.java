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
}
