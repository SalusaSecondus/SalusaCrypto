package dev.salusa.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;

import dev.salusa.crypto.hazmat.ConstantTime;

public class InternalUtilTests {
    @Test
    public void selectSmoke() {
        assertEquals(Integer.MIN_VALUE, ConstantTime.select(1, Integer.MIN_VALUE, Integer.MAX_VALUE));
        assertEquals(Integer.MAX_VALUE, ConstantTime.select(0, Integer.MIN_VALUE, Integer.MAX_VALUE));
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
