package com.vitalsshield.server.boot;

/** Published after each {@link BootSequence} step completes. */
public record BootStepCompleted(BootStep step) {
}
