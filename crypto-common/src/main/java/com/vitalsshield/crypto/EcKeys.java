package com.vitalsshield.crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/** EC P-256 (secp256r1) key helpers. Every other curve and algorithm is rejected. */
public final class EcKeys {

    /** id-ecPublicKey. */
    static final ASN1ObjectIdentifier EC_PUBLIC_KEY = X9ObjectIdentifiers.id_ecPublicKey;
    /** secp256r1 / prime256v1 named curve. */
    static final ASN1ObjectIdentifier P256 = X9ObjectIdentifiers.prime256v1;

    private static final String PEM_BEGIN = "-----BEGIN PRIVATE KEY-----";
    private static final String PEM_END = "-----END PRIVATE KEY-----";

    private EcKeys() {
    }

    public static KeyPair generateP256() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            return g.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("P-256 unavailable", e);
        }
    }

    public static byte[] spkiDer(PublicKey key) {
        return key.getEncoded();
    }

    /** Parses a DER SubjectPublicKeyInfo; throws IllegalArgumentException unless it is an EC key on named curve P-256. */
    public static PublicKey publicKeyFromSpki(byte[] spkiDer) {
        SubjectPublicKeyInfo spki;
        try {
            spki = SubjectPublicKeyInfo.getInstance(spkiDer);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("not a DER SubjectPublicKeyInfo", e);
        }
        requireP256(spki);
        try {
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spkiDer));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid EC public key", e);
        }
    }

    /** Throws IllegalArgumentException unless the SPKI is id-ecPublicKey with the named curve secp256r1. */
    public static void requireP256(SubjectPublicKeyInfo spki) {
        AlgorithmIdentifier alg = spki.getAlgorithm();
        if (!EC_PUBLIC_KEY.equals(alg.getAlgorithm())) {
            throw new IllegalArgumentException("key is not EC: " + alg.getAlgorithm());
        }
        if (!(alg.getParameters() instanceof ASN1ObjectIdentifier curve) || !P256.equals(curve)) {
            throw new IllegalArgumentException("EC key is not on named curve P-256");
        }
    }

    public static String toPkcs8Pem(PrivateKey key) {
        return PEM_BEGIN + "\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(key.getEncoded())
                + "\n" + PEM_END + "\n";
    }

    /** Parses a PKCS#8 "PRIVATE KEY" PEM holding an EC P-256 key. */
    public static PrivateKey fromPkcs8Pem(String pem) {
        String body = pem.replace(PEM_BEGIN, "").replace(PEM_END, "").replaceAll("\\s", "");
        try {
            PrivateKey key = KeyFactory.getInstance("EC")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
            if (((ECKey) key).getParams().getCurve().getField().getFieldSize() != 256) {
                throw new IllegalArgumentException("EC private key is not P-256");
            }
            return key;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalArgumentException("not a PKCS#8 EC P-256 private key PEM", e);
        }
    }

    static SubjectPublicKeyInfo spki(byte[] der) throws IOException {
        return SubjectPublicKeyInfo.getInstance(der);
    }
}
