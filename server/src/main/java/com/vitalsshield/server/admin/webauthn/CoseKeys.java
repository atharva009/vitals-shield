package com.vitalsshield.server.admin.webauthn;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * COSE_Key (RFC 9052/9053) to JCA, for the Protocol A re-verification that runs without the WebAuthn library. Only
 * EC2 keys with alg -7 (ES256) on curve 1 (P-256) are accepted. Includes the minimal CBOR reader that needs: a map
 * with integer keys and integer or byte-string values.
 */
public final class CoseKeys {

    private CoseKeys() {
    }

    public static PublicKey es256PublicKey(byte[] cose) {
        Map<Long, Object> m = new Cbor(cose).readIntKeyMap();
        if (!Long.valueOf(2).equals(m.get(1L))) {
            throw new IllegalArgumentException("COSE kty is not EC2");
        }
        if (!Long.valueOf(-7).equals(m.get(3L))) {
            throw new IllegalArgumentException("COSE alg is not -7 (ES256)");
        }
        if (!Long.valueOf(1).equals(m.get(-1L))) {
            throw new IllegalArgumentException("COSE crv is not 1 (P-256)");
        }
        if (!(m.get(-2L) instanceof byte[] x) || !(m.get(-3L) instanceof byte[] y) || x.length != 32 || y.length != 32) {
            throw new IllegalArgumentException("COSE x/y must be 32-byte strings");
        }
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
            ECPoint w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, spec));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid P-256 point", e);
        }
    }

    /** Just enough CBOR (RFC 8949) for a COSE_Key. */
    static final class Cbor {
        private final byte[] b;
        private int pos;

        Cbor(byte[] b) {
            this.b = b;
        }

        Map<Long, Object> readIntKeyMap() {
            int ib = next();
            if ((ib >>> 5) != 5) {
                throw new IllegalArgumentException("COSE_Key is not a CBOR map");
            }
            long n = length(ib & 0x1f);
            Map<Long, Object> out = new HashMap<>();
            for (long i = 0; i < n; i++) {
                Object k = readItem();
                Object v = readItem();
                if (!(k instanceof Long key)) {
                    throw new IllegalArgumentException("COSE_Key labels must be integers");
                }
                out.put(key, v);
            }
            if (pos != b.length) {
                throw new IllegalArgumentException("trailing bytes after COSE_Key");
            }
            return out;
        }

        private Object readItem() {
            int ib = next();
            int major = ib >>> 5;
            long arg = length(ib & 0x1f);
            return switch (major) {
                case 0 -> arg;
                case 1 -> -1 - arg;
                case 2, 3 -> {
                    if (arg > b.length - pos) {
                        throw new IllegalArgumentException("CBOR string overruns input");
                    }
                    byte[] out = java.util.Arrays.copyOfRange(b, pos, pos + (int) arg);
                    pos += (int) arg;
                    yield major == 2 ? out : new String(out, java.nio.charset.StandardCharsets.UTF_8);
                }
                default -> throw new IllegalArgumentException("unsupported CBOR major type " + major);
            };
        }

        private long length(int info) {
            if (info < 24) {
                return info;
            }
            int bytes = switch (info) {
                case 24 -> 1;
                case 25 -> 2;
                case 26 -> 4;
                default -> throw new IllegalArgumentException("unsupported CBOR length encoding");
            };
            long v = 0;
            for (int i = 0; i < bytes; i++) {
                v = (v << 8) | next();
            }
            return v;
        }

        private int next() {
            if (pos >= b.length) {
                throw new IllegalArgumentException("truncated CBOR");
            }
            return b[pos++] & 0xff;
        }
    }
}
