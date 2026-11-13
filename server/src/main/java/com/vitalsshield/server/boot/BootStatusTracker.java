package com.vitalsshield.server.boot;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/** Records each {@link BootStepCompleted} with a timestamp for the admin boot-status route. */
@Component
public class BootStatusTracker {

    public record Completed(BootStep step, Instant completedAt) {
    }

    private final List<Completed> completed = new CopyOnWriteArrayList<>();
    private final Clock clock;

    public BootStatusTracker(Clock clock) {
        this.clock = clock;
    }

    @EventListener
    public void on(BootStepCompleted event) {
        completed.add(new Completed(event.step(), clock.instant()));
    }

    public List<Completed> completed() {
        return List.copyOf(completed);
    }
}
