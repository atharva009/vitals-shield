package com.vitalsshield.server.admin.webauthn;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vitalsshield.server.testsupport.SoftwareAuthenticator;
import java.security.interfaces.ECPublicKey;
import org.junit.jupiter.api.Test;

/** COSE EC2 / ES256 to JCA; anything else is refused. */
class CoseKeysTest {

    @Test
    void es256KeyParses() {
        ECPublicKey k = (ECPublicKey) CoseKeys.es256PublicKey(SoftwareAuthenticator.create().coseKey());
        assertThat(k.getParams().getCurve().getField().getFieldSize()).isEqualTo(256);
    }

    @Test
    void otherAlgorithmsAreRefused() {
        byte[] cose = SoftwareAuthenticator.create().coseKey();
        // map(5) 01 02 03 26 ...: alg -7 is encoded as 0x26; -257 (RS256) would not fit, so flip -7 to -8 (EdDSA).
        int i = indexOf(cose, new byte[] {0x03, 0x26});
        cose[i + 1] = 0x27;
        byte[] edDsa = cose;
        assertThatThrownBy(() -> CoseKeys.es256PublicKey(edDsa)).hasMessageContaining("alg");
    }

    @Test
    void truncatedInputIsRefused() {
        byte[] cose = SoftwareAuthenticator.create().coseKey();
        byte[] cut = java.util.Arrays.copyOf(cose, cose.length - 5);
        assertThatThrownBy(() -> CoseKeys.es256PublicKey(cut)).isInstanceOf(IllegalArgumentException.class);
    }

    private static int indexOf(byte[] hay, byte[] needle) {
        for (int i = 0; i + needle.length <= hay.length; i++) {
            if (hay[i] == needle[0] && hay[i + 1] == needle[1]) {
                return i;
            }
        }
        throw new AssertionError("not found");
    }
}
