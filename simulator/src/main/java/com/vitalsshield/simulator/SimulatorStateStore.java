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
 * &lt;root&gt;/&lt;device_id&gt;/state/olk-pending.key  Protocol B: renewed key, before its first 200 (DECISIONS #85)
 * &lt;root&gt;/&lt;device_id&gt;/state/olk-pending.crt
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

    public Path olkPendingKeyFile() {
        return stateDir.resolve("olk-pending.key");
    }

    public Path olkPendingCertFile() {
        return stateDir.resolve("olk-pending.crt");
    }

    /** A renewed key and certificate that have not carried an accepted batch yet. */
    public record Pending(PrivateKey key, X509Certificate cert) {
    }

    /**
     * Persists the renewed key and certificate as pending, key first (both mode 600, atomic rename). A crash between
     * the two writes leaves a key without a certificate, which {@link #loadPending} ignores.
     */
    public void savePending(PrivateKey key, String certPem) {
        writeAtomic(olkPendingKeyFile(), EcKeys.toPkcs8Pem(key), true);
        writeAtomic(olkPendingCertFile(), certPem, true);
    }

    /**
     * The pending pair, if both files exist. If only the certificate exists, a promotion was interrupted after the key
     * rename: it is finished here (the certificate is moved over olk.crt) and empty is returned.
     */
    public Optional<Pending> loadPending() {
        boolean key = Files.exists(olkPendingKeyFile());
        boolean crt = Files.exists(olkPendingCertFile());
        if (!key && crt) {
            move(olkPendingCertFile(), olkCertFile());
            return Optional.empty();
        }
        if (!key || !crt) {
            return Optional.empty();
        }
        return Optional.of(new Pending(EcKeys.fromPkcs8Pem(read(olkPendingKeyFile())),
                parseCert(read(olkPendingCertFile()))));
    }

    /**
     * Pending becomes current after its first 200 (DECISIONS #85): atomic rename of the key over olk.key, then of the
     * certificate over olk.crt. The old key file is replaced, so it no longer exists on disk.
     */
    public void promotePending() {
        move(olkPendingKeyFile(), olkKeyFile());
        move(olkPendingCertFile(), olkCertFile());
    }

    /** Deletes a pending pair (re-enrollment). */
    public void discardPending() {
        try {
            Files.deleteIfExists(olkPendingCertFile());
            Files.deleteIfExists(olkPendingKeyFile());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void move(Path from, Path to) {
        try {
            Files.move(from, to, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot move " + from + " to " + to, e);
        }
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
        discardPending();
        writeAtomic(olkKeyFile(), EcKeys.toPkcs8Pem(olkKey), true);
        writeAtomic(olkCertFile(), certPem, false);
        writeAtomic(stateFile(), state.toJson(), false);
    }

    /** The DEK, if the key partition has one (Protocol C never creates a new one: the server would not know it). */
    public Optional<KeyPair> loadDek() {
        if (!Files.exists(dekKeyFile())) {
            return Optional.empty();
        }
        PrivateKey key = EcKeys.fromPkcs8Pem(read(dekKeyFile()));
        return Optional.of(new KeyPair(DekPublic.derive(key), key));
    }

    /**
     * Protocol C (DECISIONS #95): the new key and certificate replace the current ones (atomic renames, key first),
     * any pending pair is discarded, and the assigned boot_epoch and assignment are stored. The sequence number and
     * last measured_at are kept: streaming continues where it stopped.
     */
    public void saveReEnrollment(PrivateKey olkKey, String certPem, long bootEpoch, String assignmentId,
                                 String assignmentActiveFrom) {
        SimulatorState s = SimulatorState.fromJson(read(stateFile()));
        discardPending();
        writeAtomic(olkKeyFile(), EcKeys.toPkcs8Pem(olkKey), true);
        writeAtomic(olkCertFile(), certPem, false);
        writeAtomic(stateFile(), new SimulatorState(s.deviceId(), bootEpoch, s.sequenceNumber(), assignmentId,
                assignmentActiveFrom, s.enrolledAt(), s.lastMeasuredAt()).toJson(), false);
    }

    /**
     * Copies this device's whole directory (keys/ and state/, and the scenario file) to the same device id under
     * {@code targetRoot}: an exact clone of the device's flash, for the split-brain drill.
     */
    public Path cloneTo(Path targetRoot) {
        Path target = targetRoot.resolve(deviceDir.getFileName());
        if (Files.exists(target)) {
            throw new IllegalStateException("clone target already exists: " + target);
        }
        try (Stream<Path> walk = Files.walk(deviceDir)) {
            for (Path src : walk.sorted().toList()) {
                Path dst = target.resolve(deviceDir.relativize(src).toString());
                if (Files.isDirectory(src)) {
                    Files.createDirectories(dst);
                } else {
                    Files.copy(src, dst, StandardCopyOption.COPY_ATTRIBUTES);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot clone " + deviceDir + " to " + target, e);
        }
        return target;
    }

    /** Persists sequence_number + 1 before the caller uses it, so a crash can never reuse a number. */
    public long incrementSequence() {
        SimulatorState s = SimulatorState.fromJson(read(stateFile()));
        long next = s.sequenceNumber() + 1;
        writeAtomic(stateFile(), s.withSequenceNumber(next).toJson(), false);
        return next;
    }

    /** The next sequence number and its compressed-clock measured_at. */
    public record NextBatch(long sequenceNumber, java.time.Instant measuredAt) {
    }

    /**
     * Allocates sequence_number + 1 and measured_at = {@link CompressedClock#next}(last_measured_at, now), and persists
     * both before the caller uses them (DECISIONS #74): a crash can neither reuse a number nor move measured_at back.
     */
    public NextBatch nextBatch(java.time.Instant now) {
        SimulatorState s = SimulatorState.fromJson(read(stateFile()));
        long next = s.sequenceNumber() + 1;
        java.time.Instant last = s.lastMeasuredAt() == null ? null : java.time.Instant.parse(s.lastMeasuredAt());
        java.time.Instant measuredAt = CompressedClock.next(last, now);
        writeAtomic(stateFile(), s.withNextBatch(next, measuredAt.toString()).toJson(), false);
        return new NextBatch(next, measuredAt);
    }

    /** simulator-state/&lt;id&gt;/scenario: the live scenario, read by a running simulator before every batch. */
    public Path scenarioFile() {
        return deviceDir.resolve("scenario");
    }

    public void writeScenario(Scenario scenario) {
        writeAtomic(scenarioFile(), scenario.cliName() + "\n", false);
    }

    /** Empty if the file is missing or unreadable mid-rename. */
    public Optional<Scenario> readScenario() {
        try {
            if (!Files.exists(scenarioFile())) {
                return Optional.empty();
            }
            String v = Files.readString(scenarioFile(), StandardCharsets.US_ASCII).trim();
            return v.isEmpty() ? Optional.empty() : Optional.of(Scenario.parse(v));
        } catch (IOException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /** Stores a new assignment after the server answers 409 ASSIGNMENT_CHANGED. */
    public void updateAssignment(String assignmentId, String activeFrom) {
        SimulatorState s = SimulatorState.fromJson(read(stateFile()));
        writeAtomic(stateFile(), new SimulatorState(s.deviceId(), s.bootEpoch(), s.sequenceNumber(), assignmentId,
                activeFrom, s.enrolledAt(), s.lastMeasuredAt()).toJson(), false);
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
