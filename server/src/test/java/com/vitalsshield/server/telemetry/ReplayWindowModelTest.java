package com.vitalsshield.server.telemetry;

import static org.assertj.core.api.Assertions.assertThat;

import com.vitalsshield.server.telemetry.ReplayWindowModel.Decision;
import org.junit.jupiter.api.Test;

class ReplayWindowModelTest {

    final ReplayWindowModel w = new ReplayWindowModel();

    @Test
    void inOrder() {
        for (long s = 1; s <= 5; s++) {
            assertThat(w.offer(s)).isEqualTo(Decision.ACCEPT);
        }
        assertThat(w.last).isEqualTo(5);
        assertThat(w.bitmap).isEqualTo(0b11111L);
    }

    @Test
    void outOfOrderWithin64() {
        assertThat(w.offer(10)).isEqualTo(Decision.ACCEPT);   // bitmap ...1 (bit0 = 10)
        assertThat(w.offer(7)).isEqualTo(Decision.ACCEPT);    // bit3 = 7
        assertThat(w.bitmap).isEqualTo(0b1001L);
        assertThat(w.offer(7)).isEqualTo(Decision.DUPLICATE);
        assertThat(w.offer(12)).isEqualTo(Decision.ACCEPT);   // shift by 2: bit2 = 10, bit5 = 7, bit0 = 12
        assertThat(w.bitmap).isEqualTo(0b100101L);
        assertThat(w.last).isEqualTo(12);
    }

    @Test
    void gapOfExactly64ResetsBitmap() {
        w.offer(1);
        w.offer(2);
        assertThat(w.offer(66)).isEqualTo(Decision.ACCEPT);   // 66 - 2 = 64
        assertThat(w.bitmap).isEqualTo(1L);
        assertThat(w.offer(2)).isEqualTo(Decision.TOO_OLD);   // 64 behind
        assertThat(w.offer(3)).isEqualTo(Decision.ACCEPT);    // 63 behind, bit clear
        assertThat(w.bitmap).isEqualTo(1L | (1L << 63));
    }

    @Test
    void gapOf65() {
        w.offer(1);
        assertThat(w.offer(66)).isEqualTo(Decision.ACCEPT);   // 65 ahead
        assertThat(w.bitmap).isEqualTo(1L);
        assertThat(w.offer(1)).isEqualTo(Decision.TOO_OLD);   // 65 behind
    }

    @Test
    void duplicateOfNewest() {
        w.offer(5);
        assertThat(w.offer(5)).isEqualTo(Decision.DUPLICATE);
    }

    @Test
    void tooOld64And65Behind() {
        w.offer(100);
        assertThat(w.offer(36)).isEqualTo(Decision.TOO_OLD);  // 64 behind
        assertThat(w.offer(35)).isEqualTo(Decision.TOO_OLD);  // 65 behind
        assertThat(w.offer(37)).isEqualTo(Decision.ACCEPT);   // 63 behind
    }

    @Test
    void shiftBy63KeepsOnlyTheTopBit() {
        w.offer(1);                                            // bit0
        assertThat(w.offer(64)).isEqualTo(Decision.ACCEPT);   // jump 63: old bit0 moves to bit63
        assertThat(w.bitmap).isEqualTo(1L | (1L << 63));
        assertThat(w.offer(1)).isEqualTo(Decision.DUPLICATE); // 63 behind, bit set
    }
}
