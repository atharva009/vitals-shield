package com.vitalsshield.server.testsupport;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import tools.jackson.databind.json.JsonMapper;

/**
 * A software WebAuthn authenticator for tests and the dev seed tool. ES256 key, "none" attestation with attested
 * credential data, assertions for any challenge, origin, RP id, flags, and counter. {@link Variant} produces the
 * deliberately bad responses (wrong origin, wrong RP id, UV or UP unset, wrong challenge, counter regression,
 * tampered signature). Responses are the JSON shape of PublicKeyCredential.toJSON().
 */
public final class SoftwareAuthenticator {

    public static final int UP = 0x01;
    public static final int UV = 0x04;
    public static final int AT = 0x40;
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    /** How to produce one response. {@code challenge} null means "the one in the options". */
    public record Variant(String origin, String rpId, int flags, Long counter, byte[] challenge,
                          boolean tamperSignature, String type) {
        public static Variant good(String origin) {
            return new Variant(origin, "localhost", UP | UV, null, null, false, null);
        }

        public Variant withOrigin(String o) {
            return new Variant(o, rpId, flags, counter, challenge, tamperSignature, type);
        }

        public Variant withRpId(String r) {
            return new Variant(origin, r, flags, counter, challenge, tamperSignature, type);
        }

        public Variant withFlags(int f) {
            return new Variant(origin, rpId, f, counter, challenge, tamperSignature, type);
        }

        public Variant withCounter(long c) {
            return new Variant(origin, rpId, flags, c, challenge, tamperSignature, type);
        }

        public Variant withChallenge(byte[] c) {
            return new Variant(origin, rpId, flags, counter, c, tamperSignature, type);
        }

        public Variant tampered() {
            return new Variant(origin, rpId, flags, counter, challenge, true, type);
        }
    }

    private final KeyPair keyPair;
    private final byte[] credentialId;
    private byte[] userHandle;
    private long counter;

    private SoftwareAuthenticator(KeyPair keyPair, byte[] credentialId, byte[] userHandle, long counter) {
        this.keyPair = keyPair;
        this.credentialId = credentialId;
        this.userHandle = userHandle;
        this.counter = counter;
    }

    /** A fresh ES256 credential; counter starts at {@code initialCounter} (0 behaves like a synced passkey). */
    public static SoftwareAuthenticator create(long initialCounter) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            byte[] id = new byte[16];
            new SecureRandom().nextBytes(id);
            return new SoftwareAuthenticator(g.generateKeyPair(), id, null, initialCounter);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static SoftwareAuthenticator create() {
        return create(0);
    }

    /** A new key that claims {@code victim}'s credential id and user handle (an attacker after an SQL key swap). */
    public static SoftwareAuthenticator impersonating(SoftwareAuthenticator victim) {
        SoftwareAuthenticator fresh = create();
        return new SoftwareAuthenticator(fresh.keyPair, victim.credentialId.clone(),
                victim.userHandle == null ? null : victim.userHandle.clone(), 0);
    }

    public String credentialIdB64url() {
        return B64URL.encodeToString(credentialId);
    }

    public byte[] coseKey() {
        ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
        Cbor m = new Cbor().map(5);
        m.uint(1).uint(2);           // kty: EC2
        m.uint(3).negint(-7);        // alg: ES256
        m.negint(-1).uint(1);        // crv: P-256
        m.negint(-2).bytes(fixed32(pub.getW().getAffineX()));
        m.negint(-3).bytes(fixed32(pub.getW().getAffineY()));
        return m.toByteArray();
    }

    // ---- registration -----------------------------------------------------------------------------------------

    /** Answers {@code {"publicKey":{...}}} creation options (or the bare publicKey object). */
    public String register(String creationOptionsJson, Variant v) {
        Map<String, Object> pk = publicKey(creationOptionsJson);
        @SuppressWarnings("unchecked")
        Map<String, Object> user = (Map<String, Object>) pk.get("user");
        userHandle = B64URL_DEC.decode((String) user.get("id"));
        byte[] challenge = v.challenge() != null ? v.challenge() : B64URL_DEC.decode((String) pk.get("challenge"));
        byte[] clientData = clientData(v.type() != null ? v.type() : "webauthn.create", challenge, v.origin());
        long count = v.counter() != null ? v.counter() : counter;

        ByteArrayOutputStream authData = new ByteArrayOutputStream();
        authData.writeBytes(sha256(v.rpId().getBytes(StandardCharsets.UTF_8)));
        authData.write(v.flags() | AT);
        authData.writeBytes(uint32(count));
        authData.writeBytes(new byte[16]);                                       // AAGUID: none
        authData.write(credentialId.length >>> 8);
        authData.write(credentialId.length);
        authData.writeBytes(credentialId);
        authData.writeBytes(coseKey());

        Cbor att = new Cbor().map(3);
        att.text("fmt").text("none");
        att.text("attStmt").map(0);
        att.text("authData").bytes(authData.toByteArray());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("clientDataJSON", B64URL.encodeToString(clientData));
        response.put("attestationObject", B64URL.encodeToString(att.toByteArray()));
        response.put("transports", List.of("internal"));
        return credentialJson(response);
    }

    // ---- assertion --------------------------------------------------------------------------------------------

    /** Answers {@code {"publicKey":{...}}} request options; increments the counter unless it starts at 0. */
    public String assert_(String requestOptionsJson, Variant v) {
        Map<String, Object> pk = publicKey(requestOptionsJson);
        byte[] challenge = v.challenge() != null ? v.challenge() : B64URL_DEC.decode((String) pk.get("challenge"));
        return assertion(challenge, v);
    }

    public String assertion(byte[] challenge, Variant v) {
        if (counter > 0) {
            counter++;
        }
        long count = v.counter() != null ? v.counter() : counter;
        byte[] clientData = clientData(v.type() != null ? v.type() : "webauthn.get", challenge, v.origin());
        ByteArrayOutputStream authData = new ByteArrayOutputStream();
        authData.writeBytes(sha256(v.rpId().getBytes(StandardCharsets.UTF_8)));
        authData.write(v.flags());
        authData.writeBytes(uint32(count));
        byte[] ad = authData.toByteArray();
        byte[] sig = sign(concat(ad, sha256(clientData)));
        if (v.tamperSignature()) {
            sig[sig.length - 1] ^= 0x01;
        }
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("clientDataJSON", B64URL.encodeToString(clientData));
        response.put("authenticatorData", B64URL.encodeToString(ad));
        response.put("signature", B64URL.encodeToString(sig));
        if (userHandle != null) {
            response.put("userHandle", B64URL.encodeToString(userHandle));
        }
        return credentialJson(response);
    }

    /** {"credential": ...} request body for a finish endpoint, optionally with a ceremony id. */
    public static String finishBody(String credentialJson, String ceremonyIdOrNull) {
        Map<String, Object> body = new LinkedHashMap<>();
        if (ceremonyIdOrNull != null) {
            body.put("ceremony_id", ceremonyIdOrNull);
        }
        body.put("credential", JSON.readValue(credentialJson, Map.class));
        return JSON.writeValueAsString(body);
    }

    // ---- persistence (dev seed tool) --------------------------------------------------------------------------

    /** Writes credential id, user handle, and PKCS#8 key to {@code file} with permissions 600. */
    public void save(Path file) {
        try {
            Files.createDirectories(file.toAbsolutePath().getParent());
            String content = B64URL.encodeToString(credentialId) + "\n"
                    + (userHandle == null ? "-" : B64URL.encodeToString(userHandle)) + "\n"
                    + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()) + "\n"
                    + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()) + "\n";
            Files.writeString(file, content, StandardCharsets.US_ASCII);
            try {
                Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException ignored) {
                // non-POSIX file system
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static SoftwareAuthenticator load(Path file) {
        try {
            List<String> lines = Files.readAllLines(file, StandardCharsets.US_ASCII);
            KeyFactory kf = KeyFactory.getInstance("EC");
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(lines.get(2))));
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(lines.get(3))));
            byte[] handle = "-".equals(lines.get(1)) ? null : B64URL_DEC.decode(lines.get(1));
            return new SoftwareAuthenticator(new KeyPair(pub, priv), B64URL_DEC.decode(lines.get(0)), handle, 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---- helpers ----------------------------------------------------------------------------------------------

    private String credentialJson(Map<String, Object> response) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("type", "public-key");
        c.put("id", B64URL.encodeToString(credentialId));
        c.put("rawId", B64URL.encodeToString(credentialId));
        c.put("response", response);
        c.put("clientExtensionResults", Map.of());
        c.put("authenticatorAttachment", "platform");
        return JSON.writeValueAsString(c);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> publicKey(String optionsJson) {
        Map<String, Object> root = JSON.readValue(optionsJson, Map.class);
        if (root.get("options") instanceof Map<?, ?> o) {
            root = (Map<String, Object>) o;
        }
        return root.get("publicKey") instanceof Map<?, ?> pk ? (Map<String, Object>) pk : root;
    }

    private static byte[] clientData(String type, byte[] challenge, String origin) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", type);
        m.put("challenge", B64URL.encodeToString(challenge));
        m.put("origin", origin);
        m.put("crossOrigin", false);
        return JSON.writeValueAsString(m).getBytes(StandardCharsets.UTF_8);
    }

    private byte[] sign(byte[] data) {
        try {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(keyPair.getPrivate());
            s.update(data);
            return s.sign();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] uint32(long v) {
        return new byte[] {(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v};
    }

    private static byte[] fixed32(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int n = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - n, out, 32 - n, n);
        return out;
    }

    static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** Minimal CBOR writer (definite lengths only). */
    static final class Cbor {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        Cbor map(int n) {
            head(5, n);
            return this;
        }

        Cbor uint(long v) {
            head(0, v);
            return this;
        }

        Cbor negint(long v) {
            head(1, -1 - v);
            return this;
        }

        Cbor bytes(byte[] b) {
            head(2, b.length);
            out.writeBytes(b);
            return this;
        }

        Cbor text(String s) {
            byte[] b = s.getBytes(StandardCharsets.UTF_8);
            head(3, b.length);
            out.writeBytes(b);
            return this;
        }

        byte[] toByteArray() {
            return out.toByteArray();
        }

        private void head(int major, long v) {
            if (v < 24) {
                out.write((major << 5) | (int) v);
            } else if (v < 256) {
                out.write((major << 5) | 24);
                out.write((int) v);
            } else if (v < 65536) {
                out.write((major << 5) | 25);
                out.write((int) (v >>> 8));
                out.write((int) v);
            } else {
                out.write((major << 5) | 26);
                out.writeBytes(uint32(v));
            }
        }
    }
}
