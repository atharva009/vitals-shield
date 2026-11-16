package com.vitalsshield.crypto.encoding;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import java.util.HexFormat;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Expected hex is the output of {@code python3 scripts/golden_vectors.py} (independent stdlib implementation),
 * pasted verbatim. Inputs must stay in sync with that script.
 */
class CanonicalEncodingsTest {

    private static final HexFormat HEX = HexFormat.of();

    private static final String DEVICE_ID = "dev_wearable_019";
    private static final String BOOTSTRAP_TOKEN = "tok-ABC123";
    private static final String CRED_ID = "Y3JlZC0wMDE";
    private static final String CLINICIAN_ID = "clinician_007";
    private static final byte[] COSE_KEY_DER = range(0, 32);
    private static final byte[] OLK_CSR_DER = range(32, 96);
    private static final byte[] DEK_SPKI_DER = range(96, 160);
    private static final byte[] OLK_NEW_CSR_DER = range(160, 224);
    private static final String ISSUER_KEY_HASH = "a".repeat(64);
    private static final String SERIAL_NUMBER = "1f2e3d4c5b6a7988";
    private static final long EPOCH_MS = 1763059200000L;
    private static final byte[] NONCE = range(0, 16);
    private static final long BOOT_EPOCH = 3L;

    @Test
    void passkeyAnchorBytes() {
        assertHex(CanonicalEncodings.passkeyAnchorBytes(CRED_ID, CLINICIAN_ID, COSE_KEY_DER),
                "0000000b59334a6c5a4330774d44450000000d636c696e696369616e5f303037630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd");
    }

    @Test
    void provisioningDigest() {
        assertHex(CanonicalEncodings.provisioningDigest(DEVICE_ID, BOOTSTRAP_TOKEN, EPOCH_MS),
                "ffe6230819db65c6abae2e5fa2b0025da17a690129c523eb67678eba5b4121cf");
    }

    @Test
    void dekEnrollmentProofBytes() {
        assertHex(CanonicalEncodings.dekEnrollmentProofBytes(DEVICE_ID, BOOTSTRAP_TOKEN, OLK_CSR_DER),
                "000000106465765f7765617261626c655f3031397ca0b038ddf89e70c4b7803f11bdb6405ed73c16137f21038663d0e2875f9faeae02e99bbdd3713ac87427589a48fc45818ef9a7ecd27941142d8f6f61afb7c1");
    }

    @Test
    void dekAnchorBytes() {
        assertHex(CanonicalEncodings.dekAnchorBytes(DEVICE_ID, DEK_SPKI_DER, EPOCH_MS),
                "000000106465765f7765617261626c655f303139ade5c3f609729b72dcd7252435dfa94b03158fc6f20481b183d183086cb396190000019a7e847000");
    }

    @Test
    void olkRenewalProofBytes() {
        assertHex(CanonicalEncodings.olkRenewalProofBytes(
                        ISSUER_KEY_HASH, SERIAL_NUMBER, EPOCH_MS, NONCE, OLK_NEW_CSR_DER),
                "000000406161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616100000010316632653364346335623661373938380000019a7e847000000102030405060708090a0b0c0d0e0f71d74dcbd5103bb256e4c50a65b40f80baf983506d9260d70870ba3dc1c4d5cb");
    }

    @Test
    void reEnrollProofBytes() {
        assertHex(CanonicalEncodings.reEnrollProofBytes(DEVICE_ID, EPOCH_MS, NONCE, BOOT_EPOCH, OLK_CSR_DER),
                "000000106465765f7765617261626c655f3031390000019a7e847000000102030405060708090a0b0c0d0e0f0000000000000003ae02e99bbdd3713ac87427589a48fc45818ef9a7ecd27941142d8f6f61afb7c1");
    }

    @Test
    void quarantineApprovalDigest() {
        assertHex(CanonicalEncodings.quarantineApprovalDigest(DEVICE_ID, 10, "suspected clone", NONCE),
                "410834cc75b0c5cbfd1b9496d6250ebb5083514c5a1c9f500c3a9cafdc76cc71");
    }

    @Test
    void restoreApprovalDigest() {
        assertHex(CanonicalEncodings.restoreApprovalDigest(DEVICE_ID, NONCE),
                "7b06e2ab23e15d43f73c2650274e7480c0f8327121c8fdf53a4700e5dcc4b16e");
    }

    @Test
    void approvalDigestsRejectNonceNot16Bytes() {
        org.assertj.core.api.Assertions.assertThatThrownBy(
                () -> CanonicalEncodings.restoreApprovalDigest(DEVICE_ID, new byte[15]))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 15, 17, 32})
    void olkRenewalRejectsNonceNot16Bytes(int length) {
        assertThatIllegalArgumentException().isThrownBy(() -> CanonicalEncodings.olkRenewalProofBytes(
                ISSUER_KEY_HASH, SERIAL_NUMBER, EPOCH_MS, new byte[length], OLK_NEW_CSR_DER));
    }

    @ParameterizedTest
    @ValueSource(ints = {15, 17})
    void reEnrollRejectsNonceNot16Bytes(int length) {
        assertThatIllegalArgumentException().isThrownBy(() -> CanonicalEncodings.reEnrollProofBytes(
                DEVICE_ID, EPOCH_MS, new byte[length], BOOT_EPOCH, OLK_CSR_DER));
    }

    @Test
    void bootstrapTokenMustBeAscii() {
        assertThatIllegalArgumentException().isThrownBy(
                () -> CanonicalEncodings.provisioningDigest(DEVICE_ID, "tok-é", EPOCH_MS));
    }

    private static void assertHex(byte[] actual, String expectedHex) {
        assertThat(HEX.formatHex(actual)).isEqualTo(expectedHex);
    }

    private static byte[] range(int fromInclusive, int toExclusive) {
        byte[] out = new byte[toExclusive - fromInclusive];
        IntStream.range(0, out.length).forEach(i -> out[i] = (byte) (fromInclusive + i));
        return out;
    }
}
