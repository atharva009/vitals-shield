package com.vitalsshield.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.junit.jupiter.api.Test;

class CanonicalBytesTest {

    @Test
    void encodesFieldsBigEndianWithLengthPrefixes() {
        byte[] actual = new CanonicalBytes()
                .uint32Be(3)
                .utf8WithLength("abc")
                .int64Be(1L)
                .toByteArray();

        byte[] expected = {
                // uint32_be(3)
                0x00, 0x00, 0x00, 0x03,
                // uint32_be(len("abc") = 3) || utf8("abc")
                0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63,
                // int64_be(1)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        };
        assertThat(actual).containsExactly(expected);
    }

    @Test
    void emptyStringEncodesAsFourZeroBytes() {
        assertThat(new CanonicalBytes().utf8WithLength("").toByteArray())
                .containsExactly(0x00, 0x00, 0x00, 0x00);
    }

    @Test
    void sha256AppendsExactly32ByteDigest() throws Exception {
        byte[] input = "vitalsshield".getBytes(StandardCharsets.UTF_8);
        byte[] prefix = {0x7f};

        byte[] actual = new CanonicalBytes().raw(prefix).sha256(input).toByteArray();

        assertThat(actual).hasSize(1 + 32);
        assertThat(actual[0]).isEqualTo((byte) 0x7f);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(input);
        assertThat(java.util.Arrays.copyOfRange(actual, 1, actual.length)).containsExactly(digest);
    }

    @Test
    void negativeAndHighBitValuesAreEncodedUnsignedBigEndian() {
        assertThat(new CanonicalBytes().uint32Be(0xDEADBEEF).toByteArray())
                .containsExactly(0xDE, 0xAD, 0xBE, 0xEF);
        assertThat(new CanonicalBytes().int64Be(-1L).toByteArray())
                .containsExactly(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    }

    @Test
    void utf8LengthCountsBytesNotChars() {
        // "é" is 2 UTF-8 bytes.
        assertThat(new CanonicalBytes().utf8WithLength("é").toByteArray())
                .containsExactly(0x00, 0x00, 0x00, 0x02, 0xC3, 0xA9);
    }
}
