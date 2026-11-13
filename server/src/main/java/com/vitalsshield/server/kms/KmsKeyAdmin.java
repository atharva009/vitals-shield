package com.vitalsshield.server.kms;

import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyState;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.NotFoundException;

/** Key lifecycle operations used by hierarchy reconciliation. All calls are blocking. */
@Component
public class KmsKeyAdmin {

    private final KmsClient kms;

    public KmsKeyAdmin(KmsClient kms) {
        this.kms = kms;
    }

    /** Creates a non-exportable {@code ECC_NIST_P256} / {@code SIGN_VERIFY} key and returns its full ARN. */
    public String createP256SigningKey(String description) {
        return kms.createKey(r -> r.keySpec(KeySpec.ECC_NIST_P256)
                        .keyUsage(KeyUsageType.SIGN_VERIFY)
                        .description(description))
                .keyMetadata()
                .arn();
    }

    public String createP256SigningKey() {
        return createP256SigningKey("VitalsShield signing key");
    }

    /**
     * True only if DescribeKey succeeds and the key state is {@code Enabled}. A missing key or any other state
     * (PendingDeletion, Disabled, ...) is false. Other errors (network, auth) propagate: an unreachable KMS must not
     * be mistaken for a missing key.
     */
    public boolean describeEnabled(String keyArn) {
        try {
            return kms.describeKey(r -> r.keyId(keyArn)).keyMetadata().keyState() == KeyState.ENABLED;
        } catch (NotFoundException e) {
            return false;
        }
    }

    /** DER SubjectPublicKeyInfo from GetPublicKey. */
    public byte[] publicKeySpki(String keyArn) {
        return kms.getPublicKey(r -> r.keyId(keyArn)).publicKey().asByteArray();
    }

    /** Best-effort cleanup for keys created by a rebuild that did not commit. */
    public void scheduleDeletion(String keyArn, int pendingWindowInDays) {
        kms.scheduleKeyDeletion(r -> r.keyId(keyArn).pendingWindowInDays(pendingWindowInDays));
    }
}
