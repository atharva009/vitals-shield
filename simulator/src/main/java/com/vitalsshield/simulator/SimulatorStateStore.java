package com.vitalsshield.simulator;

import com.vitalsshield.crypto.EcKeys;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

/**
 * On-disk device state, laid out like a wearable's flash (spec Section 4, "Wearable Persistence"):
 * <pre>
 * &lt;root&gt;/&lt;device_id&gt;/keys/dek.key      key partition: survives a state reset
 * &lt;root&gt;/&lt;device_id&gt;/state/olk.key     state partition
 * &lt;root&gt;/&lt;device_id&gt;/state/olk.crt
 * &lt;root&gt;/&lt;device_id&gt;/state/state.json
 * </pre>
 * Every write goes to a temp file in the same directory and is then renamed with ATOMIC_MOVE. Private keys are
 * created with POSIX permissions rw------- where the file system supports it.
 */
public final class SimulatorStateStore {

    static final Set<PosixFilePermission> OWNER_RW = PosixFilePermissions.fromString("rw-------");

    /** Everything the state partition holds after enrollment. */
    public record Enrollment(PrivateKey olkKey, X509Certificate olkCert, SimulatorState state) {
    }

    private final Path deviceDir;
    private final Path keysDir;
    private final Path stateDir;

    public SimulatorStateStore(Path root, String deviceId) {
        this.deviceDir = root.resolve(deviceId);
        this.keysDir = deviceDir.resolve("keys");
        this.stateDir = deviceDir.resolve("state");
    }

    public Path deviceDir() {
        return deviceDir;
    }

    public Path dekKeyFile() {
        return keysDir.resolve("dek.key");
    }

    public Path olkKeyFile() {
        return stateDir.resolve("olk.key");
    }

    public Path olkCertFile() {
        return stateDir.resolve("olk.crt");
    }

    public Path stateFile() {
        return stateDir.resolve("state.json");
    }

    /** Loads the DEK, creating and persisting a new one if the key partition is empty. */
    public KeyPair loadOrCreateDek() {
        if (Files.exists(dekKeyFile())) {
            PrivateKey key = EcKeys.fromPkcs8Pem(read(dekKeyFile()));
            return new KeyPair(DekPublic.derive(key), key);
        }
        KeyPair dek = EcKeys.generateP256();
        writeAtomic(dekKeyFile(), EcKeys.toPkcs8Pem(dek.getPrivate()), true);
        return dek;
    }

    public Optional<Enrollment> load() {
        if (!Files.exists(olkKeyFile()) || !Files.exists(olkCertFile()) || !Files.exists(stateFile())) {
            return Optional.empty();
        }
        return Optional.of(new Enrollment(EcKeys.fromPkcs8Pem(read(olkKeyFile())), parseCert(read(olkCertFile())),
                SimulatorState.fromJson(read(stateFile()))));
    }

    public void saveEnrollment(PrivateKey olkKey, String certPem, SimulatorState state) {
        writeAtomic(olkKeyFile(), EcKeys.toPkcs8Pem(olkKey), true);
        writeAtomic(olkCertFile(), certPem, false);
        writeAtomic(stateFile(), state.toJson(), false);
    }

    /** Persists sequence_number + 1 before the caller uses it, so a crash can never reuse a number. */
    public long incrementSequence() {
        SimulatorState s = SimulatorState.fromJson(read(stateFile()));
        long next = s.sequenceNumber() + 1;
        writeAtomic(stateFile(), s.withSequenceNumber(next).toJson(), false);
        return next;
    }

    /** Stores a new assignment after the server answers 409 ASSIGNMENT_CHANGED. */
    public void updateAssignment(String assignmentId, String activeFrom) {
        SimulatorState s = SimulatorState.fromJson(read(stateFile()));
        writeAtomic(stateFile(), new SimulatorState(s.deviceId(), s.bootEpoch(), s.sequenceNumber(), assignmentId,
                activeFrom, s.enrolledAt()).toJson(), false);
    }

    /** Erases the state partition only; keys/dek.key survives. */
    public void resetState() {
        deleteTree(stateDir);
    }

    /** Erases both partitions, including the DEK. */
    public void factoryWipe() {
        deleteTree(stateDir);
        deleteTree(keysDir);
    }

    static X509Certificate parseCert(String pem) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
        } catch (CertificateException e) {
            throw new IllegalStateException("corrupt certificate", e);
        }
    }

    static void writeAtomic(Path target, String content, boolean secret) {
        Path dir = target.getParent();
        Path tmp = null;
        try {
            Files.createDirectories(dir);
            FileAttribute<?>[] attrs = secret && posix() ? new FileAttribute<?>[] {
                PosixFilePermissions.asFileAttribute(OWNER_RW)} : new FileAttribute<?>[0];
            tmp = Files.createTempFile(dir, "." + target.getFileName(), ".tmp", attrs);
            Files.writeString(tmp, content, StandardCharsets.US_ASCII);
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            tmp = null;
        } catch (IOException e) {
            throw new UncheckedIOException("cannot write " + target, e);
        } finally {
            if (tmp != null) {
                try {
                    Files.deleteIfExists(tmp);
                } catch (IOException ignored) {
                    // best effort
                }
            }
        }
    }

    static boolean posix() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }

    private static String read(Path p) {
        try {
            return Files.readString(p, StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void deleteTree(Path dir) {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.delete(p);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
