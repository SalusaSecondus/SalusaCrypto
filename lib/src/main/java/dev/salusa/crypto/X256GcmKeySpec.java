package dev.salusa.crypto;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * A {@link SecretKey} for use with {@link X256Gcm} in a way similar to a
 * {@link SecretKeySpec}.
 * 
 * <p>
 * You should reuse instances of this class as much as possible as it performs a
 * somewhat expensive key-derivation step at creation time. By reusing
 * instances, you only pay that cost once per key.
 * 
 * <p>
 * This class is immutable and thread-safe.
 */
public final class X256GcmKeySpec implements SecretKey, KeySpec {
    private static final int AES_BLOCK_LENGTH = 16;
    private static final byte[] ZERO_BLOCK = new byte[AES_BLOCK_LENGTH];
    private final byte[] k1;
    private final SecretKey k;

    private X256GcmKeySpec(SecretKey k, byte[] k1) {
        this.k = k;
        this.k1 = k1;
    }

    /**
     * Creates an instance of this class using the first 32 bytes of {@code k}
     * starting at {@code offset} inclusive.
     * 
     * <p>
     * The default Java provider for "AES/ECB/NoPadding" is used for key derivation.
     */
    public static X256GcmKeySpec getInstance(final byte[] k, int offset)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        return getInstance(new SecretKeySpec(k, offset, 32, "AES"));
    }

    /**
     * Creates an instance of this class using the first 32 bytes of {@code k}
     * starting at {@code offset} inclusive.
     * 
     * @param providerName the name of the provider used for key derivation
     */
    public static X256GcmKeySpec getInstance(final byte[] k, int offset, String providerName)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
        return getInstance(new SecretKeySpec(k, offset, 32, "AES"), providerName);
    }

    /**
     * Creates an instance of this class using the first 32 bytes of {@code k}
     * starting at {@code offset} inclusive.
     * 
     * @param provider the provider used for key derivation
     */
    public static X256GcmKeySpec getInstance(final byte[] k, int offset, Provider provider)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        return getInstance(new SecretKeySpec(k, offset, 32, "AES"), provider);
    }

    /**
     * Creates an instance of this class using {@code k}.
     * 
     * <p>
     * The default Java provider for "AES/ECB/NoPadding" is used for key derivation.
     * 
     * @throws InvalidKeyException if {@code k} is not exactly 32 bytes long.
     */
    public static X256GcmKeySpec getInstance(final byte[] k)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        if (k.length != 32) {
            throw new InvalidKeyException("Key must be 32 bytes long.");
        }
        return getInstance(new SecretKeySpec(k, "AES"));
    }

    /**
     * Creates an instance of this class using {@code k}.
     * 
     * @param providerName the name of the provider used for key derivation
     * 
     * @throws InvalidKeyException if {@code k} is not exactly 32 bytes long.
     */
    public static X256GcmKeySpec getInstance(final byte[] k, String providerName)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
        if (k.length != 32) {
            throw new InvalidKeyException("Key must be 32 bytes long.");
        }
        return getInstance(new SecretKeySpec(k, "AES"), providerName);
    }

    /**
     * Creates an instance of this class using {@code k}.
     * 
     * @param provider the provider used for key derivation
     * 
     * @throws InvalidKeyException if {@code k} is not exactly 32 bytes long.
     */
    public static X256GcmKeySpec getInstance(final byte[] k, Provider provider)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        if (k.length != 32) {
            throw new InvalidKeyException("Key must be 32 bytes long.");
        }
        return getInstance(new SecretKeySpec(k, "AES"), provider);
    }

    /**
     * Creates an instance of this class using {@code k}.
     * 
     * <p>
     * The default Java provider for "AES/ECB/NoPadding" is used for key derivation.
     */
    public static X256GcmKeySpec getInstance(final SecretKey k)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        final Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        return getInstance(k, c);
    }

    /**
     * Creates an instance of this class using {@code k}.
     * 
     * @param providerName the name of the provider used for key derivation
     */
    public static X256GcmKeySpec getInstance(final SecretKey k, String providerName)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
        final Cipher c = Cipher.getInstance("AES/ECB/NoPadding", providerName);
        return getInstance(k, c);
    }

    /**
     * Creates an instance of this class using {@code k}.
     * 
     * @param provider the provider used for key derivation
     */
    public static X256GcmKeySpec getInstance(final SecretKey k, Provider provider)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        final Cipher c = Cipher.getInstance("AES/ECB/NoPadding", provider);
        return getInstance(k, c);
    }

    private static X256GcmKeySpec getInstance(final SecretKey k, final Cipher aesCipher) throws InvalidKeyException {
        aesCipher.init(Cipher.ENCRYPT_MODE, k);
        byte[] l;
        try {
            l = aesCipher.doFinal(ZERO_BLOCK);
        } catch (final IllegalBlockSizeException | BadPaddingException e) {
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

    /**
     * Returns the string "XAES-256-GCM".
     */
    @Override
    public String getAlgorithm() {
        return "XAES-256-GCM";
    }

    /**
     * Returns the string "RAW".
     */
    @Override
    public String getFormat() {
        return "RAW";
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

    /**
     * Returns the raw AES key {@code k} used to create this object.
     */
    public SecretKey getK() {
        return k;
    }

    @Override 
    public boolean equals(Object obj) {
        if (obj instanceof X256GcmKeySpec other) {
            return MessageDigest.isEqual(k1, other.k1);
        }
        return false;
    }

    @Override 
    public int hashCode() {
        return k.hashCode();
    }
}
