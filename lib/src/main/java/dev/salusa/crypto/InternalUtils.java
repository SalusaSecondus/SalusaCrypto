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
}
