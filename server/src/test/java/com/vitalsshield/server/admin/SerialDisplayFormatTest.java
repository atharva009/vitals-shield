package com.vitalsshield.server.admin;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SerialDisplayFormatTest {

    @Test
    void oddLengthGetsOneLeadingZero() {
        // Real Phase 4 serial: 39 hex digits; openssl printed 0CB611FB8DDC...
        assertThat(SerialDisplayFormat.toOpenSslHex("cb611fb8ddc2d0be2daf451ebd80f3904b8e902"))
                .isEqualTo("0CB611FB8DDC2D0BE2DAF451EBD80F3904B8E902");
    }

    @Test
    void evenLengthIsJustUppercased() {
        assertThat(SerialDisplayFormat.toOpenSslHex("5f3126f0df41a08f6d87a388b2bc4e2d682fb954"))
                .isEqualTo("5F3126F0DF41A08F6D87A388B2BC4E2D682FB954");
    }

    @Test
    void firstByteAbove7fIsNotPadded() {
        // Display mirrors openssl's hex of the value; a high first nibble needs no padding when the length is even.
        assertThat(SerialDisplayFormat.toOpenSslHex("9a")).isEqualTo("9A");
        assertThat(SerialDisplayFormat.toOpenSslHex("ff01")).isEqualTo("FF01");
        assertThat(SerialDisplayFormat.toOpenSslHex("abc")).isEqualTo("0ABC");
    }
}
