package com.vitalsshield.server.testsupport;

import com.vitalsshield.simulator.SimulatorMain;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** The simulator CLI in-process against test listeners. */
public final class SimulatorCli {

    public record Run(int exit, String out) {
    }

    private final Path stateRoot;
    private final Path trustFile;
    private final TestPorts.Listeners ports;

    public SimulatorCli(Path stateRoot, Path trustFile, TestPorts.Listeners ports) {
        this.stateRoot = stateRoot;
        this.trustFile = trustFile;
        this.ports = ports;
    }

    public Run run(String... args) {
        List<String> all = new ArrayList<>(List.of(args));
        all.addAll(List.of("--state-dir", stateRoot.toString(), "--trust-file", trustFile.toString(),
                "--public-url", "https://127.0.0.1:" + ports.pub(), "--mtls-url", "https://127.0.0.1:" + ports.mtls()));
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(buf, true, StandardCharsets.UTF_8);
        int exit = SimulatorMain.run(all.toArray(String[]::new), ps, ps);
        return new Run(exit, buf.toString(StandardCharsets.UTF_8));
    }

    public Run enroll(String deviceId, String token) {
        return run("enroll", "--device-id", deviceId, "--token", token);
    }
}
