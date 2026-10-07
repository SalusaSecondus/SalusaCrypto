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

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }


  static byte[] decodeHex(String hex) {
    if (hex.length() % 2 != 0) {
      throw new IllegalArgumentException("Input length must be even");
    }
    byte[] result = new byte[hex.length() / 2];
    for (int x = 0; x < hex.length() / 2; x++) {
      result[x] = (byte) Integer.parseInt(hex.substring(2 * x, 2 * x + 2), 16);
    }
    return result;
  }
}
