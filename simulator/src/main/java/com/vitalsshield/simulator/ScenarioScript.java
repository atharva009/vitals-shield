package com.vitalsshield.simulator;

import java.util.ArrayList;
import java.util.List;

/** {@code --script "resting:15,drift:6,acute:2"}: batch counts per scenario, then the last scenario holds. */
public final class ScenarioScript {

    public record Step(Scenario scenario, int batches) {
    }

    private final List<Step> steps;

    private ScenarioScript(List<Step> steps) {
        this.steps = List.copyOf(steps);
    }

    public static ScenarioScript parse(String spec) {
        List<Step> steps = new ArrayList<>();
        for (String part : spec.split(",")) {
            String[] kv = part.trim().split(":");
            if (kv.length != 2) {
                throw new IllegalArgumentException("script step must be scenario:count, got: " + part);
            }
            int n = Integer.parseInt(kv[1].trim());
            if (n < 1) {
                throw new IllegalArgumentException("script count must be positive: " + part);
            }
            steps.add(new Step(Scenario.parse(kv[0]), n));
        }
        if (steps.isEmpty()) {
            throw new IllegalArgumentException("empty script");
        }
        return new ScenarioScript(steps);
    }

    /** The scenario of the {@code index}-th batch sent (0-based); after the script ends, the last scenario. */
    public Scenario at(long index) {
        long seen = 0;
        for (Step s : steps) {
            seen += s.batches();
            if (index < seen) {
                return s.scenario();
            }
        }
        return steps.get(steps.size() - 1).scenario();
    }

    public long totalBatches() {
        return steps.stream().mapToLong(Step::batches).sum();
    }

    public List<Step> steps() {
        return steps;
    }
}
