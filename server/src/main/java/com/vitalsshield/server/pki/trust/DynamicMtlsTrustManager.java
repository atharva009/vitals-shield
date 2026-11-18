package com.vitalsshield.server.pki.trust;

import com.vitalsshield.server.pki.CertificateProfiles;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Set;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Client-certificate trust for the mTLS listener. Runs inside the TLS handshake on a Netty event loop, so it uses
 * only in-memory data: {@link TrustAnchorSource} (read on every call, never cached here) and
 * {@link CertificateDenyList}. No JDBC.
 *
 * <p>Steps: (1) only chain[0] is used; anything else the client sends is ignored. (2) PKIX validation of
 * [leaf, current Device Intermediate] against the current Root, revocation off. (3) Leaf policy: CA:FALSE,
 * digitalSignature, EKU clientAuth, and AKI == current Device Intermediate SKI. The AKI rule is a VitalsShield policy
 * on top of RFC 5280 path validation, not an RFC 5280 requirement. (4) Deny-list.
 */
@Component
public class DynamicMtlsTrustManager extends X509ExtendedTrustManager {

    private static final Logger log = LoggerFactory.getLogger(DynamicMtlsTrustManager.class);

    static final String CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2";

    private final TrustAnchorSource anchors;
    private final CertificateDenyList denyList;
    private final Clock clock;
    private volatile SupersededUseRecorder supersededUse = SupersededUseRecorder.NONE;

    public DynamicMtlsTrustManager(TrustAnchorSource anchors, CertificateDenyList denyList, Clock clock) {
        this.anchors = anchors;
        this.denyList = denyList;
        this.clock = clock;
    }

    /** DECISIONS #94: the post-drain trap (optional; unit tests construct this class without it). */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setSupersededUseRecorder(SupersededUseRecorder recorder) {
        this.supersededUse = recorder == null ? SupersededUseRecorder.NONE : recorder;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        validate(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        validate(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        validate(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        throw new UnsupportedOperationException("client-certificate trust manager only");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
        throw new UnsupportedOperationException("client-certificate trust manager only");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
        throw new UnsupportedOperationException("client-certificate trust manager only");
    }

    /** Sent to clients in CertificateRequest: only the current Device Intermediate. */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[] {anchors.deviceIntermediate()};
    }

    private void validate(X509Certificate[] chain) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("no client certificate");
        }
        // 1. Leaf only. The client's intermediates are never trusted or used.
        X509Certificate leaf = chain[0];
        X509Certificate deviceInt = anchors.deviceIntermediate();
        X509Certificate root = anchors.root();
        Instant now = clock.instant();
        String serial = leaf.getSerialNumber().toString(16);

        // 2. PKIX: signatures, validity windows, CA Basic Constraints / pathLen / keyCertSign, name chaining.
        try {
            CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(List.of(leaf, deviceInt));
            PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(root, null)));
            params.setRevocationEnabled(false);
            params.setDate(Date.from(now));
            CertPathValidator.getInstance("PKIX").validate(path, params);
        } catch (GeneralSecurityException e) {
            // Keep the CertPathValidatorException (reason EXPIRED, NOT_YET_VALID, ...) as the cause so JSSE can pick a
            // specific alert (DECISIONS #37).
            throw reject("PKIX validation failed: " + e.getMessage(), serial, akiHex(leaf), e);
        }

        // 3. Leaf policy.
        if (leaf.getBasicConstraints() != -1) {
            throw reject("leaf is a CA", serial, akiHex(leaf));
        }
        boolean[] ku = leaf.getKeyUsage();
        if (ku == null || !ku[0]) {
            throw reject("leaf lacks digitalSignature", serial, akiHex(leaf));
        }
        List<String> eku = leaf.getExtendedKeyUsage();
        if (eku == null || !eku.contains(CLIENT_AUTH_OID)) {
            throw reject("leaf lacks EKU clientAuth", serial, akiHex(leaf));
        }
        byte[] aki = CertificateProfiles.authorityKeyIdentifier(leaf);
        if (aki == null || !Arrays.equals(aki, CertificateProfiles.subjectKeyIdentifier(deviceInt))) {
            throw reject("leaf AKI is not the current Device Intermediate SKI", serial, akiHex(leaf));
        }

        // 4. Deny-list.
        CertKey key = CertKey.from(leaf);
        if (denyList.isDenied(key, now)) {
            // A RENEWED certificate after its grace: report it to the post-drain trap (in-memory queue offer only).
            denyList.entry(key).filter(e -> "SUPERSEDED".equals(e.reason()))
                    .ifPresent(e -> supersededUse.recordSupersededUse(key, now));
            // Cause with reason REVOKED, so JSSE can send certificate_revoked (44) where it supports it (DECISIONS #37).
            throw reject("certificate is deny-listed", key.serial(), key.issuerKeyHash(),
                    new CertPathValidatorException("certificate is revoked", null, null, -1,
                            CertPathValidatorException.BasicReason.REVOKED));
        }
    }

    private static CertificateException reject(String reason, String serial, String issuerHash) {
        return reject(reason, serial, issuerHash, null);
    }

    private static CertificateException reject(String reason, String serial, String issuerHash, Throwable cause) {
        log.info("mTLS client certificate rejected: {} (serial={}, issuer_key_hash={})", reason, serial, issuerHash);
        return cause == null ? new CertificateException(reason) : new CertificateException(reason, cause);
    }

    private static String akiHex(X509Certificate leaf) {
        try {
            byte[] aki = CertificateProfiles.authorityKeyIdentifier(leaf);
            return aki == null ? "none" : java.util.HexFormat.of().formatHex(aki);
        } catch (RuntimeException e) {
            return "unparseable";
        }
    }
}
