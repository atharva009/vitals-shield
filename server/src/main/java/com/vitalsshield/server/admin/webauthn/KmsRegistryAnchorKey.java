package com.vitalsshield.server.admin.webauthn;

import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.server.kms.KmsKeyAdmin;
import com.vitalsshield.server.kms.KmsSigner;
import com.vitalsshield.server.pki.ActiveKmsKeys;
import com.vitalsshield.server.pki.KeyPurpose;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/** The ACTIVE REGISTRY_ANCHOR key from kms_keys. Public keys are cached per ARN (a rebuild changes the ARN). */
@Component
public class KmsRegistryAnchorKey implements RegistryAnchorKey {

    private final KmsSigner signer;
    private final ActiveKmsKeys keys;
    private final KmsKeyAdmin keyAdmin;
    private final Map<String, PublicKey> publicKeys = new ConcurrentHashMap<>();

    public KmsRegistryAnchorKey(KmsSigner signer, ActiveKmsKeys keys, KmsKeyAdmin keyAdmin) {
        this.signer = signer;
        this.keys = keys;
        this.keyAdmin = keyAdmin;
    }

    @Override
    public byte[] signDigest(byte[] sha256Digest) {
        return signer.signDigestBlocking(keys.requireArn(KeyPurpose.REGISTRY_ANCHOR), sha256Digest);
    }

    @Override
    public PublicKey publicKey() {
        String arn = keys.requireArn(KeyPurpose.REGISTRY_ANCHOR);
        return publicKeys.computeIfAbsent(arn, a -> EcKeys.publicKeyFromSpki(keyAdmin.publicKeySpki(a)));
    }
}
