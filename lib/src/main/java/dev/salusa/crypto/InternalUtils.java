package dev.salusa.crypto;

/**
 * DO NOT USE
 * 
 * <p>This class and all methods on it are intended for internal use by the SalusaCrypto package.
 * No promises are made about these APIs or functions and they may change or be deleted even on patch version changes.
 * Do not use this under any circumstances.
 */
final class InternalUtils {
    static final byte[] EMPTY_ARRAY = new byte[0];

    static byte[] cloneArray(byte[] arr) {
        if (arr == null || arr.length == 0) {
            return EMPTY_ARRAY;
        }
        return arr.clone();
    }

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
}
