package com.vitalsshield.server.boot;

import com.vitalsshield.server.admin.AdminSetupCode;
import com.vitalsshield.server.admin.KmsHealthMonitor;
import com.vitalsshield.server.gateway.ListenerManager;
import com.vitalsshield.server.pki.IssuedSerialLedger;
import com.vitalsshield.server.pki.trust.CertKey;
import com.vitalsshield.server.pki.CrlService;
import com.vitalsshield.server.pki.GatewayTlsMaterial;
import com.vitalsshield.server.pki.HierarchyReconciler;
import com.vitalsshield.server.pki.ReconcileResult;
import com.vitalsshield.server.pki.TrustAnchors;
import com.vitalsshield.server.pki.trust.CertificateDenyList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

/**
 * Ordered startup after context refresh (Flyway has already migrated): reconcile hierarchy, issue gateway TLS
 * material, reload trust anchors, seed the deny-list, publish CRLs, issue the admin setup code, and only then bind the
 * listeners. A sweep of stale serial reservations runs right after reconciliation. Runs on the boot thread, so the
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
    private final CrlService crls;
    private final IssuedSerialLedger ledger;
    private final AdminSetupCode adminCode;
    private final KmsHealthMonitor kmsHealth;
    private final ListenerManager listeners;
    private final ApplicationEventPublisher events;

    public BootSequence(HierarchyReconciler reconciler, GatewayTlsMaterial gatewayTls, TrustAnchors trustAnchors,
                        CertificateDenyList denyList, CrlService crls, IssuedSerialLedger ledger,
                        AdminSetupCode adminCode, KmsHealthMonitor kmsHealth, ListenerManager listeners,
                        ApplicationEventPublisher events) {
        this.reconciler = reconciler;
        this.gatewayTls = gatewayTls;
        this.trustAnchors = trustAnchors;
        this.denyList = denyList;
        this.crls = crls;
        this.ledger = ledger;
        this.adminCode = adminCode;
        this.kmsHealth = kmsHealth;
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
        // DECISIONS #49: first health check right after reconciliation, then every 30 s. It never rebuilds.
        log.info("KMS health after reconcile: {}", kmsHealth.checkNow().state());
        kmsHealth.start();

        // Void reservations that never activated (crash after sign, lost race) before the deny-list is seeded, so the
        // seed and the CRL both include them (DECISIONS #38).
        List<CertKey> voided = ledger.sweepStale();
        log.info("Boot step SERIALS_SWEPT: {} stale reservation(s) voided", voided.size());
        events.publishEvent(new BootStepCompleted(BootStep.SERIALS_SWEPT));

        gatewayTls.issue();
        events.publishEvent(new BootStepCompleted(BootStep.GATEWAY_TLS_ISSUED));

        trustAnchors.reload();
        events.publishEvent(new BootStepCompleted(BootStep.TRUST_ANCHORS_LOADED));

        denyList.seedFromDb();
        denyList.startPeriodicRefresh();
        events.publishEvent(new BootStepCompleted(BootStep.DENY_LIST_SEEDED));

        // Sign both CRLs now so the first HTTP GET is served from the cache (DECISIONS.md #27).
        crls.publishAll();
        crls.startExpiryWatch();
        events.publishEvent(new BootStepCompleted(BootStep.CRLS_PUBLISHED));

        adminCode.issue();
        events.publishEvent(new BootStepCompleted(BootStep.ADMIN_CODE_ISSUED));

        // Last step, always: ports open only after every check above has passed.
        listeners.bindAll();
        events.publishEvent(new BootStepCompleted(BootStep.LISTENERS_BOUND));
        return result;
    }
}
