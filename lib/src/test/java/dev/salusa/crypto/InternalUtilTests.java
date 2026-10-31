package dev.salusa.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

public class InternalUtilTests {
    @Test
    public void leftShiftByZeroLeavesArrayUnchanged() {
        byte[] value = {(byte) 0x12, (byte) 0xAB};

        assertEquals(0, InternalUtils.leftShift(value, 0));
        assertArrayEquals(new byte[] {(byte) 0x12, (byte) 0xAB}, value);
    }

    @Test
    public void leftShiftPropagatesBitsAcrossBytes() {
        byte[] value = {(byte) 0x80, 0x01, (byte) 0xFF};

        assertEquals(1, InternalUtils.leftShift(value, 1));
        assertArrayEquals(new byte[] {0x00, 0x03, (byte) 0xFE}, value);
    }

    @Test
    public void leftShiftByPartialByteReturnsOverflowBits() {
        byte[] value = {(byte) 0xAB, (byte) 0xCD};

        assertEquals(0x0A, InternalUtils.leftShift(value, 4));
        assertArrayEquals(new byte[] {(byte) 0xBC, (byte) 0xD0}, value);
    }

    @Test
    public void leftShiftByEightMovesBytesAndReturnsFirstByte() {
        byte[] value = {0x12, 0x34, 0x56};

        assertEquals(0x12, InternalUtils.leftShift(value, 8));
        assertArrayEquals(new byte[] {0x34, 0x56, 0x00}, value);
    }

    @Test
    public void leftShiftOfEmptyArrayReturnsZero() {
        assertEquals(0, InternalUtils.leftShift(new byte[0], 4));
    }

    @Test
    public void leftShiftRejectsOutOfRangeShifts() {
        assertThrows(IllegalArgumentException.class, () -> InternalUtils.leftShift(new byte[] {0x01}, -1));
        assertThrows(IllegalArgumentException.class, () -> InternalUtils.leftShift(new byte[] {0x01}, 9));
    }

    @Test 
    public void cloneArrayNullYieldsEmpty() {
        assertSame(InternalUtils.EMPTY_ARRAY, InternalUtils.cloneArray(null));
    }

    @Test 
    public void cloneEmptyNullYieldsEmpty() {
        assertSame(InternalUtils.EMPTY_ARRAY, InternalUtils.cloneArray(new byte[0]));
    }
}
