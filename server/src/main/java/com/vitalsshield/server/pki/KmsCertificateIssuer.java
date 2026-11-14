package com.vitalsshield.server.pki;

import com.vitalsshield.server.kms.KmsSigner;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.springframework.stereotype.Component;

/** Signs leaves with the KMS key of the current ACTIVE Device Intermediate / Server TLS CA. */
@Component
public class KmsCertificateIssuer implements CertificateIssuer {

    private final CaIssuerRepository issuers;
    private final KmsSigner kmsSigner;
    private final CertificateProfiles profiles;

    public KmsCertificateIssuer(CaIssuerRepository issuers, KmsSigner kmsSigner, CertificateProfiles profiles) {
        this.issuers = issuers;
        this.kmsSigner = kmsSigner;
        this.profiles = profiles;
    }

    @Override
    public X509Certificate issueDeviceLeaf(String deviceId, SubjectPublicKeyInfo spki, Duration ttl,
                                           BigInteger serial) {
        CaIssuer ca = issuers.requireActive(KeyPurpose.DEVICE_INTERMEDIATE);
        return profiles.deviceLeaf(deviceId, spki, ca.certificate(), ttl,
                KmsContentSigner.forKmsKey(kmsSigner, ca.kmsArn()), serial);
    }

    @Override
    public X509Certificate issueGatewayLeaf(PublicKey key, Duration ttl) {
        CaIssuer ca = issuers.requireActive(KeyPurpose.SERVER_TLS_CA);
        return profiles.gatewayLeaf(SubjectPublicKeyInfo.getInstance(key.getEncoded()), ca.certificate(), ttl,
                KmsContentSigner.forKmsKey(kmsSigner, ca.kmsArn()));
    }
}
