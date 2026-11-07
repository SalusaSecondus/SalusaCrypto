package dev.salusa.crypto.hazmat;

/**
 * A collection of constant time utilities.
 * <p>For boolean-type input, 0 is false and everything else is true.
 * For output, false is always 0 and true is always 1.
 * 
 * @since 1.2.0
 */
public final class ConstantTime {
    private ConstantTime() {
    }

    /** Equivalent to {@code val != 0 ? 1 : 0} */
    public static int isNonZero(int val) {
        return ((val | -val) >>> 31) & 0x01;
    }

    /** Equivalent to {@code val == 0 ? 1 : 0} */
    public static int isZero(int val) {
        return 1 - isNonZero(val);
    }

    /** Equivalent to {@code x == y ? 1 : 0} */
    public static int isEqual(int x, int y) {
        final int difference = x - y;
        // Difference is 0 iff x == y
        return isZero(difference);
    }

    /** Performs a left shift of {@code shift} bits.
     * 
     * <p>Constant time on everything <em>except</em> the length of {@code arr}.
     * 
     * @throws IllegalArgumentException if {@code shift < 0} or {@code shift > 8}.
     */
    public static byte leftShift(byte[] arr, int shift) {
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

    /** Equivalent to {@code selector != 0 ? a : b} */
    public static int select(int selector, int a, int b) {
        final int mask = isZero(selector) - 1;

        final int combined = a ^ b;

        return b ^ (combined & mask);
    }

}
