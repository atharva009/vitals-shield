package com.vitalsshield.server.boot;

import com.vitalsshield.server.pki.GatewayTlsMaterial;
import com.vitalsshield.server.pki.HierarchyReconciler;
import com.vitalsshield.server.pki.ReconcileResult;
import com.vitalsshield.server.pki.TrustAnchors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

/**
 * Ordered startup after context refresh (Flyway has already migrated):
 * reconcile hierarchy, issue gateway TLS material, reload trust anchors. Runs on the boot thread, so the blocking KMS
 * calls are allowed here. Disabled with {@code vitalsshield.boot.enabled=false} (schema-only tests).
 */
@Component
@ConditionalOnProperty(name = "vitalsshield.boot.enabled", havingValue = "true", matchIfMissing = true)
public class BootSequence implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootSequence.class);

    private final HierarchyReconciler reconciler;
    private final GatewayTlsMaterial gatewayTls;
    private final TrustAnchors trustAnchors;
    private final ApplicationEventPublisher events;

    public BootSequence(HierarchyReconciler reconciler, GatewayTlsMaterial gatewayTls, TrustAnchors trustAnchors,
                        ApplicationEventPublisher events) {
        this.reconciler = reconciler;
        this.gatewayTls = gatewayTls;
        this.trustAnchors = trustAnchors;
        this.events = events;
    }

    @Override
    public void run(ApplicationArguments args) {
        runBoot();
    }

    public ReconcileResult runBoot() {
        ReconcileResult result = reconciler.reconcile();
        log.info("Boot step RECONCILED: {}", result);
        events.publishEvent(new BootStepCompleted(BootStep.RECONCILED));

        gatewayTls.issue();
        events.publishEvent(new BootStepCompleted(BootStep.GATEWAY_TLS_ISSUED));

        trustAnchors.reload();
        events.publishEvent(new BootStepCompleted(BootStep.TRUST_ANCHORS_LOADED));

        // ===================================================================================
        // PHASE 2 HOOK: bind listeners (8443 mTLS, 8444, 8445) here as the final step, then
        // publish new BootStepCompleted(BootStep.BIND_LISTENERS). Nothing binds before this.
        // ===================================================================================
        return result;
    }
}
