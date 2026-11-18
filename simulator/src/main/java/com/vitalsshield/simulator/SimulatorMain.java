package com.vitalsshield.simulator;

import java.io.PrintStream;
import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;
import java.util.HashMap;
import java.util.Map;

/**
 * CLI:
 * <pre>
 * simulator enroll --device-id X --token T [--state-dir D] [--trust-file F] [--public-url U] [--mtls-url U]
 * simulator ping [--device-id X] [...]
 * simulator run [--device-id X] [--interval-ms 1000] [--count N, 0 = forever] [--scenario S]
 *               [--script "resting:15,drift:6,acute:2"] [...]
 * simulator scenario [--device-id X] --set S      (S: resting, exertion, drift, acute, low-perfusion-critical)
 * simulator reset-state [--device-id X] [--state-dir D]
 * simulator factory-wipe [--device-id X] [--state-dir D]
 * simulator re-enroll [--device-id X] [--state-dir D]         Protocol C now (for example after a clinician restore)
 * simulator clone --device-id X --to-state-dir D [--state-dir S]   copy keys/ and state/ (split-brain drill)
 * </pre>
 * Every command accepts --state-dir (default simulator-state).
 *
 * <p>Exit codes: 0 done; 1 error; 2 usage; 3 refused (revoked, quarantined, or forbidden; never recovered
 * automatically); 4 the certificate expired and Protocol C could not run (for example no DEK); 5 a clinician must act
 * (re-enrollment answered REAUTH_REQUIRED, BOOT_EPOCH_INVALID, BOOT_EPOCH_REGRESSION or DEVICE_NOT_ACTIVE).
 */
public final class SimulatorMain {

    static final String DEFAULT_DEVICE = "dev_wearable_019";

    private SimulatorMain() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    /** Entry point usable in-process (tests). Returns the exit code. */
    public static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length == 0) {
            err.println("usage: simulator <enroll|ping|run|scenario|reset-state|factory-wipe|re-enroll|clone> "
                    + "[--device-id X] [--token T] [--interval-ms MS] [--count N] [--scenario S] [--script S:N,...] "
                    + "[--set S] [--state-dir D] [--to-state-dir D] [--trust-file F] [--public-url U] [--mtls-url U]\n"
                    + "exit codes: 0 ok, 1 error, 2 usage, 3 refused/revoked, 4 cert expired and unrecoverable, "
                    + "5 REAUTH_REQUIRED (clinician action)");
            return 2;
        }
        Map<String, String> opts;
        try {
            opts = parseOptions(args);
        } catch (IllegalArgumentException e) {
            err.println(e.getMessage());
            return 2;
        }
        Simulator.Config config = new Simulator.Config(
                opts.getOrDefault("device-id", DEFAULT_DEVICE),
                Path.of(opts.getOrDefault("state-dir", "simulator-state")),
                Path.of(opts.getOrDefault("trust-file", "var/trust/root-ca.pem")),
                URI.create(opts.getOrDefault("public-url", "https://127.0.0.1:8444")),
                URI.create(opts.getOrDefault("mtls-url", "https://127.0.0.1:8443")));
        Simulator sim = new Simulator(config, Clock.systemUTC());
        try {
            switch (args[0]) {
                case "enroll" -> {
                    String token = opts.get("token");
                    if (token == null) {
                        err.println("enroll needs --token");
                        return 2;
                    }
                    return switch (sim.enroll(token)) {
                        case Simulator.EnrollOutcome.AlreadyEnrolled a -> {
                            out.println("ALREADY_ENROLLED serial=" + a.cert().getSerialNumber().toString(16));
                            yield 0;
                        }
                        case Simulator.EnrollOutcome.Enrolled e -> {
                            out.println("ENROLLED serial=" + e.cert().getSerialNumber().toString(16)
                                    + " boot_epoch=" + e.bootEpoch()
                                    + " not_after=" + e.cert().getNotAfter().toInstant());
                            yield 0;
                        }
                        case Simulator.EnrollOutcome.Failed f -> {
                            out.println("ENROLL_FAILED status=" + f.status() + " body=" + f.body());
                            yield 1;
                        }
                    };
                }
                case "ping" -> {
                    GatewayClient.Response r = sim.ping();
                    out.println(r.status() + " " + r.body());
                    return r.status() == 200 ? 0 : 1;
                }
                case "run" -> {
                    Simulator.StreamOptions so;
                    try {
                        so = new Simulator.StreamOptions(
                                opts.containsKey("scenario") ? Scenario.parse(opts.get("scenario")) : null,
                                opts.containsKey("script") ? ScenarioScript.parse(opts.get("script")) : null);
                    } catch (IllegalArgumentException e) {
                        err.println(e.getMessage());
                        return 2;
                    }
                    return sim.stream(Long.parseLong(opts.getOrDefault("interval-ms", "1000")),
                            Long.parseLong(opts.getOrDefault("count", "0")), out, so);
                }
                case "scenario" -> {
                    String set = opts.get("set");
                    if (set == null) {
                        out.println("SCENARIO " + sim.store().readScenario().map(Scenario::cliName).orElse("(none)"));
                        return 0;
                    }
                    Scenario sc;
                    try {
                        sc = Scenario.parse(set);
                    } catch (IllegalArgumentException e) {
                        err.println(e.getMessage());
                        return 2;
                    }
                    sim.store().writeScenario(sc);
                    out.println("SCENARIO_SET " + sc.cliName() + " " + sim.store().scenarioFile());
                    return 0;
                }
                case "reset-state" -> {
                    sim.store().resetState();
                    out.println("STATE_RESET " + sim.store().deviceDir());
                    return 0;
                }
                case "re-enroll" -> {
                    Integer exit = sim.recoverByReEnroll(out, "manual");
                    return exit == null ? 0 : exit;
                }
                case "clone" -> {
                    String to = opts.get("to-state-dir");
                    if (to == null) {
                        err.println("clone needs --to-state-dir");
                        return 2;
                    }
                    Path target = sim.store().cloneTo(Path.of(to));
                    out.println("CLONED " + sim.store().deviceDir() + " -> " + target);
                    return 0;
                }
                case "factory-wipe" -> {
                    sim.store().factoryWipe();
                    out.println("FACTORY_WIPED " + sim.store().deviceDir());
                    return 0;
                }
                default -> {
                    err.println("unknown command: " + args[0]);
                    return 2;
                }
            }
        } catch (Exception e) {
            err.println("ERROR " + e);
            return 1;
        }
    }

    static Map<String, String> parseOptions(String[] args) {
        Map<String, String> opts = new HashMap<>();
        for (int i = 1; i < args.length; i++) {
            String a = args[i];
            if (!a.startsWith("--") || i + 1 >= args.length) {
                throw new IllegalArgumentException("expected --name value, got: " + a);
            }
            opts.put(a.substring(2), args[++i]);
        }
        return opts;
    }
}
