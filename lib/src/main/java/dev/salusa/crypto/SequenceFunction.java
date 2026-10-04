package dev.salusa.crypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.SecretKey;

public class SequenceFunction implements Cloneable {
    private static final FunctionIndicator F_SEQMAC = new FunctionIndicator(1);
    private static final FunctionIndicator F_SEQHSH = new FunctionIndicator(2);
    private static final byte[] SEQHSH_I = "SEQHSH_I".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SEQHSH_O = "SEQHSH_O".getBytes(StandardCharsets.UTF_8);

    private final int blockSize;
    private final FunctionIndicator f;
    private byte[] k;
    private MessageDigest iBase;
    private MessageDigest oBase;
    private MessageDigest iHash;

    private long n;
    private long currSegLength;
    private byte[] cachedInner;

    public static SequenceMac buildSha256Mac(SecretKey key) {
        return buildSha256Mac(key, null);
    }

    public static SequenceMac buildSha256Mac(SecretKey key, byte[] customizationString) {
        try {
            return new SequenceMac(checkedGetKey(key), customizationString, MessageDigest.getInstance("SHA-256"), 64);
        } catch (final NoSuchAlgorithmException ex) {
            throw new UnsupportedOperationException("SHA-256 doesn't exist?", ex);
        }
    }

    public static SequenceHash buildSha256() {
        return buildSha256(null);
    }

    public static SequenceHash buildSha256(byte[] customizationString) {
        try {
            return new SequenceHash(customizationString, MessageDigest.getInstance("SHA-256"), 64);
        } catch (final NoSuchAlgorithmException ex) {
            throw new UnsupportedOperationException("SHA-256 doesn't exist?", ex);
        }
    }

    private SequenceFunction(final byte[] key, final FunctionIndicator type, byte[] s, MessageDigest h, final int blockSize) {
        this.k = InternalUtils.cloneArray(key);
        this.blockSize = blockSize;
        this.f = type;
        init(h, k, s);
    }

    public SequenceFunction update(byte[] data) {
        return update(data, 0, data.length);
    }

    public SequenceFunction update(byte[] data, int offset, int length) {
        assertNotInFinal();
        currSegLength += length;
        if (length > 0) {
            iHash.update(data, offset, length);
        }
        iHash.update(encodeLSBF(currSegLength));
        currSegLength = 0;
        n++;
        return this;
    }

    public SequenceFunction update(ByteBuffer data) {
        assertNotInFinal();
        currSegLength += data.remaining();
        iHash.update(data);
        iHash.update(encodeLSBF(currSegLength));
        currSegLength = 0;
        n++;
        return this;
    }

    public SequenceFunction updatePartial(byte[] data) {
        return updatePartial(data, 0, data.length);
    }

    public SequenceFunction updatePartial(byte[] data, int offset, int length) {
        assertNotInFinal();
        currSegLength += length;
        if (length > 0) {
            iHash.update(data, offset, length);
        }
        return this;
    }

    public SequenceFunction updatePartial(ByteBuffer data) {
        assertNotInFinal();
        currSegLength += data.remaining();
        iHash.update(data);
        return this;
    }

    public SequenceFunction reset() {
        try {
            iHash = (MessageDigest) iBase.clone();
            n = 0;
            currSegLength = 0;
            cachedInner = null;
        } catch (final CloneNotSupportedException ex) {
            throw new UnsupportedOperationException("SequenceFunction requires that MessageDigest is cloneable", ex);
        }
        return this;
    }

    public byte[] doFinal() {
        if (cachedInner == null) {
            cachedInner = iHash.digest();
            iHash = null;
        }
        try {
            MessageDigest oHash = (MessageDigest) oBase.clone();
            oHash.update(encodeMSBF(n));
            oHash.update(encodeMSBF(oBase.getDigestLength()));
            return oHash.digest(cachedInner);
        } catch (final CloneNotSupportedException ex) {
            throw new UnsupportedOperationException("SequenceFunction requires that MessageDigest is cloneable", ex);
        }
    }

    public byte[] doFinal(byte[] input) {
        update(input);
        return doFinal();
    }

    public byte[] doFinal(ByteBuffer input) {
        update(input);
        return doFinal();
    }

    public SequenceFunction cloneWithCustomization(byte[] customization) {
        SequenceFunction result = clone();
        result.init(result.oBase, k, customization);
        return result;
    }

    public SequenceFunction clone() {
        try {
            SequenceFunction result = (SequenceFunction) super.clone();
            result.iHash = (MessageDigest) result.iHash.clone();

            // No need to clone oBase and iBase as they never change
            return result;
        } catch (final CloneNotSupportedException ex) {
            throw new UnsupportedOperationException("SequenceFunction requires that MessageDigest is cloneable", ex);
        }
    }

    public int getOutputLength() {
        return oBase.getDigestLength();
    }

    // Helper functions
    private void init(MessageDigest h, byte[] k, byte[] s) {
        try {
            oBase = (MessageDigest) h.clone();
            oBase.reset();
            iBase = (MessageDigest) oBase.clone();

            byte[] k_i = derive(k, oBase, (byte) 0x55, blockSize);
            byte[] k_o = derive(k, oBase, (byte) 0xaa, blockSize);
            byte[] sPrime = derive(s, oBase, (byte) 0x00, blockSize);

            oBase.update(k_o);
            oBase.update(headerO(blockSize, f, length(s), length(k)));
            oBase.update(sPrime);

            iBase.update(k_i);
            iBase.update(headerI(blockSize, f, length(k)));
            iHash = (MessageDigest) iBase.clone();
        } catch (final CloneNotSupportedException ex) {
            throw new UnsupportedOperationException("SequenceFunction requires that MessageDigest is cloneable", ex);
        }
    }

    private static int length(byte[] arr) {
        if (arr == null) {
            return 0;
        }
        return arr.length;
    }

    private void assertNotInFinal() {
        if (cachedInner != null) {
            throw new IllegalStateException("Must be reset() before updates are allowed");
        }
    }

    // Package private for testing
    static void encodeMSBF(long val, byte[] dst, int offset) {
        if (val < 0) {
            throw new IllegalArgumentException();
        }
        final ByteBuffer result = ByteBuffer.wrap(dst, offset, 16);
        result.order(ByteOrder.BIG_ENDIAN);
        result.position(result.position() + 8);
        result.putLong(val);
    }

    static byte[] encodeMSBF(long val) {
        final byte[] result = new byte[16];
        encodeMSBF(val, result, 0);
        return result;
    }

    static byte[] encodeLSBF(long val) {
        if (val < 0) {
            throw new IllegalArgumentException();
        }
        final ByteBuffer result = ByteBuffer.allocate(16);
        result.order(ByteOrder.LITTLE_ENDIAN);
        result.putLong(val);
        return result.array();
    }

    static byte[] pad(byte[] x, int b) {
        final int len = length(x);
        if (len == 0) {
            return new byte[b];
        }
        if (len % b == 0) {
            return x;
        }
        final int padLen = b - (len % b);
        return Arrays.copyOf(x, len + padLen);
    }

    static <E extends Exception> void encode(byte[] input, ThrowingConsumer<byte[], E> f) throws E {
        long len = length(input);
        f.accept(input);
        f.accept(encodeLSBF(len));
    }

    static byte[] derive(byte[] i, MessageDigest h, byte tweak, int blockSize) {
        final byte[] iPrime;
        if (length(i) < blockSize) {
            iPrime = pad(i, blockSize);
        } else {
            iPrime = pad(h.digest(i), blockSize);
        }
        iPrime[0] ^= tweak;
        return iPrime;
    }

    static byte[] headerI(int blockSize, FunctionIndicator f, int keyLen) {
        final byte[] result = Arrays.copyOf(SEQHSH_I, SEQHSH_I.length + 32);
        f.copyTo(result, SEQHSH_I.length);
        encodeMSBF(keyLen, result, SEQHSH_I.length + 16);
        return pad(result, blockSize);
    }

    static byte[] headerO(int blockSize, FunctionIndicator f, int sLen, int keyLen) {
        final byte[] result = Arrays.copyOf(SEQHSH_O, SEQHSH_O.length + 48);

        f.copyTo(result, SEQHSH_O.length);
        encodeMSBF(sLen, result, SEQHSH_O.length + 16);
        encodeMSBF(keyLen, result, SEQHSH_O.length + 32);
        return pad(result, blockSize);
    }

    private static final class FunctionIndicator {
        final byte[] value;

        public FunctionIndicator(long i) {
            value = encodeMSBF(i);
        }

        public void copyTo(byte[] dst, int offset) {
            System.arraycopy(value, 0, dst, offset, value.length);
        }
    }

    private static byte[] checkedGetKey(SecretKey key) {
        if (!key.getFormat().equalsIgnoreCase("RAW")) {
            throw new IllegalArgumentException("Keys to SequenceMac must use a RAW format. Not " + key.getFormat());
        }
        if (!key.getAlgorithm().equalsIgnoreCase("GENERIC") && !key.getAlgorithm().equalsIgnoreCase("SequenceMAC")) {
            throw new IllegalArgumentException("Keys to SequenceMac must have either the algorithm \"GENERIC\" or \"SequenceMAC\". Not " + key.getAlgorithm());
        }
        final byte[] rawKey = key.getEncoded();
        if (rawKey == null) {
            throw new IllegalArgumentException("Keys to SequenceMac must be extractable");
        }
        if (rawKey.length < 32) {
            throw new IllegalArgumentException("Keys to SequenceMac must be at least 32 bytes long. Not " + rawKey.length);
        }
        return rawKey;
    }

    public static final class SequenceHash extends SequenceFunction {
        private SequenceHash(byte[] s, MessageDigest h, final int blockSize) {
            super(null, F_SEQHSH, s, h, blockSize);
        }
    }

    public static final class SequenceMac extends SequenceFunction {
        private SequenceMac(final byte[] key, byte[] s, MessageDigest h, final int blockSize) {
            super(key, F_SEQMAC, s, h, blockSize);
        }
    }
}