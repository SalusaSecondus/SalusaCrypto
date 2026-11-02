package dev.salusa.crypto;

import java.security.SecureRandom;

/**
 * DO NOT USE
 * 
 * <p>
 * This class and all methods on it are intended for internal use by the
 * SalusaCrypto package.
 * No promises are made about these APIs or functions and they may change or be
 * deleted even on patch version changes.
 * Do not use this under any circumstances.
 */
final class InternalUtils {
    static final byte[] EMPTY_ARRAY = new byte[0];
    static final ThreadLocal<SecureRandom> RNG = ThreadLocal.withInitial(SecureRandom::new);

    static byte[] randomBytes(int length) {
        byte[] result = new byte[length];
        RNG.get().nextBytes(result);
        return result;
    }

    static byte[] cloneArray(byte[] arr) {
        if (arr == null || arr.length == 0) {
            return EMPTY_ARRAY;
        }
        return arr.clone();
    }

    /** Constant time */
    static byte leftShift(byte[] arr, int shift) {
        if (shift > 8 || shift < 0) {
            throw new IllegalArgumentException();
        }
        if (arr.length == 0) {
            return 0;
        }
        final byte mask = (byte) ((1 << shift) - 1);
        final byte result = (byte) ((arr[0] >>> (8 - shift)) & mask);

        for (int idx = 0; idx < arr.length; idx++) {
            byte carry = 0;
            if (idx < arr.length - 1) {
                carry = (byte) ((arr[idx + 1] >> (8 - shift)) & mask);
            }
            arr[idx] <<= shift;
            arr[idx] |= carry;
        }
        return result;
    }

    /** Constant-time. Requires that selector be 1 or 0. */
    static int select(int selector, int a, int b) {
        final int mask = (1 - selector) - 1;
        // Mask == -1 (all bits 1) iff selector != 0
        // Mask == 0 (all bits 0) iff selector == 0

        final int combined = a ^ b;

        return b ^ (combined & mask);
    }
}
