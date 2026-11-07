package dev.salusa.crypto.hazmat;

import static dev.salusa.crypto.hazmat.ConstantTime.isEqual;
import static dev.salusa.crypto.hazmat.ConstantTime.isNonZero;
import static dev.salusa.crypto.hazmat.ConstantTime.isZero;
import static dev.salusa.crypto.hazmat.ConstantTime.select;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ConstantTimeTests {
    public static List<Integer> singleInput() {
        return Arrays.asList(
            Integer.MIN_VALUE,
            Integer.MIN_VALUE + 1,
            Byte.MIN_VALUE - 1,
            (int) Byte.MIN_VALUE,
            Byte.MIN_VALUE + 1,
            -2,
            -1,
            0,
            1,
            2,
            Byte.MAX_VALUE - 1,
            (int) Byte.MAX_VALUE,
            Byte.MAX_VALUE + 1,
            Integer.MAX_VALUE - 1,
            Integer.MAX_VALUE);
    }

    public static List<Arguments> twoInputs() {
        List<Integer> single = singleInput();
        List<Arguments> result = new ArrayList<>();
        for (Integer a: single) {
            for (Integer b: single) {
                result.add(Arguments.of(a, b));
            }
        }
        return result;
    }

    public static List<Arguments> threeInputs() {
        List<Integer> single = singleInput();
        List<Arguments> result = new ArrayList<>();
        for (Integer a: single) {
            for (Integer b: single) {
                for (Integer c: single) {
                    result.add(Arguments.of(a, b, c));
                }
            }
        }
        return result;
    }

        @Test
    public void leftShiftByZeroLeavesArrayUnchanged() {
        byte[] value = {(byte) 0x12, (byte) 0xAB};

        assertEquals(0, ConstantTime.leftShift(value, 0));
        assertArrayEquals(new byte[] {(byte) 0x12, (byte) 0xAB}, value);
    }

    @Test
    public void leftShiftPropagatesBitsAcrossBytes() {
        byte[] value = {(byte) 0x80, 0x01, (byte) 0xFF};

        assertEquals(1, ConstantTime.leftShift(value, 1));
        assertArrayEquals(new byte[] {0x00, 0x03, (byte) 0xFE}, value);
    }

    @Test
    public void leftShiftByPartialByteReturnsOverflowBits() {
        byte[] value = {(byte) 0xAB, (byte) 0xCD};

        assertEquals(0x0A, ConstantTime.leftShift(value, 4));
        assertArrayEquals(new byte[] {(byte) 0xBC, (byte) 0xD0}, value);
    }

    @Test
    public void leftShiftByEightMovesBytesAndReturnsFirstByte() {
        byte[] value = {0x12, 0x34, 0x56};

        assertEquals(0x12, ConstantTime.leftShift(value, 8));
        assertArrayEquals(new byte[] {0x34, 0x56, 0x00}, value);
    }

    @Test
    public void leftShiftOfEmptyArrayReturnsZero() {
        assertEquals(0, ConstantTime.leftShift(new byte[0], 4));
    }

    @Test
    public void leftShiftRejectsOutOfRangeShifts() {
        assertThrows(IllegalArgumentException.class, () -> ConstantTime.leftShift(new byte[] {0x01}, -1));
        assertThrows(IllegalArgumentException.class, () -> ConstantTime.leftShift(new byte[] {0x01}, 9));
    }

    @ParameterizedTest 
    @MethodSource("singleInput")
    public void testIsZero(Integer val) {
        assertEquals(val == 0 ? 1 : 0, isZero(val));
    }

    @ParameterizedTest 
    @MethodSource("singleInput")
    public void testIsNonZero(Integer val) {
        assertEquals(val != 0 ? 1 : 0, isNonZero(val));
    }

    @ParameterizedTest 
    @MethodSource("twoInputs")
    public void testEqual(Integer a, Integer b) {
        assertEquals(a == b ? 1 : 0, isEqual(a, b));
    }

    @ParameterizedTest
    @MethodSource("threeInputs")
    public void testSelect(Integer selector, Integer a, Integer b) {
        assertEquals(selector !=0 ? a : b, select(selector, a, b));
    }
}
