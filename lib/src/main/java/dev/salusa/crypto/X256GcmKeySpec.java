package dev.salusa.crypto;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public final class X256GcmKeySpec implements  Key, KeySpec {
    private static final int AES_BLOCK_LENGTH = 16;
    private static final byte[] ZERO_BLOCK = new byte[AES_BLOCK_LENGTH];
    private final byte[] k1;
    private final SecretKey k;
    
    private X256GcmKeySpec(SecretKey k, byte[] k1) {
        this.k = k;
        this.k1 = k1;
    }
    
    public static X256GcmKeySpec getInstance(final byte[] k, int offset) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        return getInstance(new SecretKeySpec(k, offset, 32, "AES"));
    }

    public static X256GcmKeySpec getInstance(final byte[] k) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        if (k.length != 32) {
            throw new InvalidKeyException("Key must be 32 bytes long.");
        }
        return getInstance(new SecretKeySpec(k, "AES"));
    }

    public static X256GcmKeySpec getInstance(final SecretKey k) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        final Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        return getInstance(k, c);
    }

    private static X256GcmKeySpec getInstance(final SecretKey k, final Cipher aesCipher) throws InvalidKeyException {
        aesCipher.init(Cipher.ENCRYPT_MODE, k);
        byte[] l;
        try {
            l = aesCipher.doFinal(ZERO_BLOCK);
        } catch (final IllegalBlockSizeException|BadPaddingException e) {
           throw new IllegalArgumentException("Cipher did not properly implement AES-ECB", e);
        }
        if (l.length != AES_BLOCK_LENGTH) {
            throw new IllegalArgumentException("Cipher returned output of wrong length: " + l.length);
        }
        final byte topBit = InternalUtils.leftShift(l, 1);

        if (topBit != 0) {
            l[l.length - 1] ^= 0b10000111;
        }
        return new X256GcmKeySpec(k, l);
    }

    @Override
    public String getAlgorithm() {
        return "XAES-256-GCM";
    }

    @Override
    public String getFormat() {
        return k.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        return k.getEncoded();
    }

    void applyK1(byte[] m) {
        if (m.length != 2 * AES_BLOCK_LENGTH) {
            throw new IllegalArgumentException();
        }
        for (int idx = 0; idx < m.length; idx++) {
            m[idx] ^= k1[idx % AES_BLOCK_LENGTH];
        }
    }

    public SecretKey getK() {
        return k;
    }
}
