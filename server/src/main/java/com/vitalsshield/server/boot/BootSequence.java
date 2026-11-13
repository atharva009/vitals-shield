package com.vitalsshield.server.boot;

import com.vitalsshield.server.gateway.ListenerManager;
import com.vitalsshield.server.pki.GatewayTlsMaterial;
import com.vitalsshield.server.pki.HierarchyReconciler;
import com.vitalsshield.server.pki.ReconcileResult;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

/**
 * Ordered startup after context refresh (Flyway has already migrated): reconcile hierarchy, issue gateway TLS
 * material, reload trust anchors, seed the deny-list, and only then bind the listeners. Runs on the boot thread, so the
 * blocking KMS and JDBC calls are allowed here. Disabled with {@code vitalsshield.boot.enabled=false}, in which case
 * nothing binds.
 */
@Component
@ConditionalOnProperty(name = "vitalsshield.boot.enabled", havingValue = "true", matchIfMissing = true)
public class BootSequence implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootSequence.class);

    private final HierarchyReconciler reconciler;
    private final GatewayTlsMaterial gatewayTls;
    private final TrustAnchors trustAnchors;
    private final CertificateDenyList denyList;
    private final ListenerManager listeners;
    private final ApplicationEventPublisher events;

    public BootSequence(HierarchyReconciler reconciler, GatewayTlsMaterial gatewayTls, TrustAnchors trustAnchors,
                        CertificateDenyList denyList, ListenerManager listeners, ApplicationEventPublisher events) {
        this.reconciler = reconciler;
        this.gatewayTls = gatewayTls;
        this.trustAnchors = trustAnchors;
        this.denyList = denyList;
        this.listeners = listeners;
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

        denyList.seedFromDb();
        denyList.startPeriodicRefresh();
        events.publishEvent(new BootStepCompleted(BootStep.DENY_LIST_SEEDED));

        // Last step, always: ports open only after every check above has passed.
        listeners.bindAll();
        events.publishEvent(new BootStepCompleted(BootStep.LISTENERS_BOUND));
        return result;
    }
}
