package dev.salusa.crypto;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.util.HexFormat;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * An implementation of
 * <a href="https://c2sp.org/XAES-256-GCM@v1.0.1">XAES-256-GCM</a> (v1.0.1).
 * 
 * <p>
 * The API for this class is based heavily on Java's {@link Cipher} API.
 * 
 * @see <a href="https://c2sp.org/XAES-256-GCM@v1.0.1">c2sp.org/XAES-256-GCM</a>
 * @since 1.1.0
 */
public final class X256Gcm {
    private static final int AES_BLOCK_LENGTH = 16;
    private static final byte[] M_BASE = HexFormat.of()
            .parseHex("0001580000000000000000000000000000025800000000000000000000000000");

    private final Cipher ecb;
    private final Cipher gcm;
    private IvParameterSpec iv;

    /**
     * Returns an instance of this object with underlying implementations provided
     * by calls to {@link Cipher#getInstance(String)} with no specified provider.
     * 
     * @see Cipher#getInstance(String)
     */
    public static X256Gcm getInstance() {
        try {
            final Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding");
            final Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            return new X256Gcm(ecb, gcm);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new UnexpectedException(
                    "Both AES/ECB/NoPadding and AES/GCM/NoPadding are expected to always be present.", ex);
        }
    }

    /**
     * Returns an instance of this object with underlying implementations provided
     * by calls to {@link Cipher#getInstance(String, String)} with the specified
     * provider.
     * {@code providerName} must provide both "AES/ECB/NoPadding" and
     * "AES/GCM/NoPadding".
     * 
     * @param providerName the name of the provider
     * @see Cipher#getInstance(String, String)
     */
    public static X256Gcm getInstance(String providerName)
            throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException {
        final Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding", providerName);
        final Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding", providerName);
        return new X256Gcm(ecb, gcm);
    }

    /**
     * Returns an instance of this object with underlying implementations provided
     * by calls to {@link Cipher#getInstance(String, Provider)} with the specified
     * provider.
     * {@code provider} must provide both "AES/ECB/NoPadding" and
     * "AES/GCM/NoPadding".
     * 
     * @param provider the provider
     * @see Cipher#getInstance(String, Provider)
     */
    public static X256Gcm getInstance(Provider provider) throws NoSuchAlgorithmException, NoSuchPaddingException {
        final Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding", provider);
        final Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding", provider);
        return new X256Gcm(ecb, gcm);
    }

    private X256Gcm(final Cipher ecb, final Cipher gcm) {
        this.ecb = ecb;
        this.gcm = gcm;
    }

    /**
     * Initializes this object for <em>encryption</em> or <em>wrapping</em> with a
     * random IV.
     * 
     * You can then retrieve the random IV by calling {@link #getIV()}. If you do
     * not retrieve and save the IV, you will not be able to decrypt the data later
     * on.
     * 
     * @param cipherMode either {@link Cipher#ENCRYPT_MODE} or
     *                   {@link Cipher#WRAP_MODE}
     * 
     * @throws IllegalArgumentException if {@code cipherMode} is not
     *                                  {@link Cipher#ENCRYPT_MODE} or
     *                                  {@link Cipher#WRAP_MODE}
     */
    public void init(final int cipherMode, final X256GcmKeySpec key) throws InvalidKeyException {
        if (cipherMode != Cipher.ENCRYPT_MODE && cipherMode != Cipher.WRAP_MODE) {
            throw new IllegalArgumentException(
                    "IvParameterSpec may only be omitted for Cipher.ENCRYPT_MODE and Cipher.WRAP_MODE");
        }
        try {
            init(cipherMode, key, new IvParameterSpec(InternalUtils.randomBytes(24)));
        } catch (final InvalidAlgorithmParameterException ex) {
            throw new UnexpectedException(ex);
        }
    }

    /**
     * Initializes this cipher with a key and a set of algorithm parameters.
     * 
     * <p>
     * Equivalent to
     * {@link Cipher#init(int, Key, java.security.spec.AlgorithmParameterSpec)}
     * 
     * @see Cipher#init(int, Key, java.security.spec.AlgorithmParameterSpec)
     */
    public void init(final int cipherMode, final X256GcmKeySpec key, final IvParameterSpec ivSpec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        final byte[] rawIv = ivSpec.getIV();
        if (rawIv.length != 24) {
            throw new InvalidAlgorithmParameterException("IV must be 192 bits (24 bytes) long, not " + rawIv.length);
        }
        iv = ivSpec;
        final byte[] m = M_BASE.clone();
        System.arraycopy(rawIv, 0, m, 4, 12);
        System.arraycopy(rawIv, 0, m, 20, 12);

        key.applyK1(m);
        ecb.init(Cipher.ENCRYPT_MODE, key.getK());
        byte[] rawKx;
        try {
            rawKx = ecb.doFinal(m);
        } catch (final IllegalBlockSizeException | BadPaddingException ex) {
            throw new UnexpectedException(ex);
        }
        if (rawKx.length != 2 * AES_BLOCK_LENGTH) {
            throw new UnexpectedException("AES-ECB returned result of wrong length: " + rawKx.length);
        }
        final SecretKey kx = new SecretKeySpec(rawKx, "AES");

        final GCMParameterSpec gcmSpec = new GCMParameterSpec(128, rawIv, 12, 12);
        gcm.init(cipherMode, kx, gcmSpec);
    }

    /**
     * Finishes a multiple-part encryption or decryption operation, depending on how
     * this cipher was initialized.
     * 
     * @see Cipher#doFinal()
     */
    public byte[] doFinal() throws IllegalBlockSizeException, BadPaddingException {
        return gcm.doFinal();
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation.
     * 
     * @see Cipher#doFinal(byte[])
     */
    public byte[] doFinal(byte[] input) throws IllegalBlockSizeException, BadPaddingException {
        return gcm.doFinal(input);
    }

    /**
     * Finishes a multiple-part encryption or decryption operation, depending on how
     * this cipher was initialized.
     * 
     * @see Cipher#doFinal(byte[], int)
     */
    public int doFinal(byte[] output, int outputOffset)
            throws IllegalBlockSizeException, ShortBufferException, BadPaddingException {
        return gcm.doFinal(output, outputOffset);
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation.
     * 
     * @see Cipher#doFinal(byte[], int, int)
     */
    public byte[] doFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        return gcm.doFinal(input, inputOffset, inputLen);
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation.
     * 
     * @see Cipher#doFinal(byte[], int, int, byte[])
     */
    public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return gcm.doFinal(input, inputOffset, inputLen, output);
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation.
     * 
     * @see Cipher#doFinal(byte[], int, int, byte[], int)
     */
    public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return gcm.doFinal(input, inputOffset, inputLen, output, outputOffset);
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation.
     * 
     * @see Cipher#doFinal(ByteBuffer, ByteBuffer)
     */
    public int doFinal(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return gcm.doFinal(input, output);
    }

    /**
     * Returns the IV currently in use by this object.
     * 
     * @see Cipher#getIV()
     */
    public byte[] getIV() {
        return iv.getIV();
    }

    /**
     * Returns the length in bytes that an output buffer would need to be in order
     * to hold the result of the next {@code update} or {@code doFinal} operation,
     * given the input length {@code inputLen} (in bytes).
     * 
     * @see Cipher#getOutputSize(int)
     */
    public int getOutputSize(int inputLen) {
        return gcm.getOutputSize(inputLen);
    }

    /**
     * Returns the provider of this Cipher object.
     * 
     * @see Cipher#getProvider()
     */
    public Provider getProvider() {
        return gcm.getProvider();
    }

    @Override
    public String toString() {
        return "X256Gcm from " + gcm.getProvider();
    }

    /**
     * Unwrap a previously wrapped key.
     * 
     * @see Cipher#unwrap(byte[], String, int)
     */
    public Key unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        return gcm.unwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    }

    /**
     * Continues a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized), processing another data part.
     * 
     * @see Cipher#update(byte[])
     */
    public byte[] update(byte[] input) {
        return gcm.update(input);
    }

    /**
     * Continues a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized), processing another data part.
     * 
     * @see Cipher#update(byte[], int, int)
     */
    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        return gcm.update(input, inputOffset, inputLen);
    }

    /**
     * Continues a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized), processing another data part.
     * 
     * @see Cipher#update(byte[], int, int, byte[])
     */
    public int update(byte[] input, int inputOffset, int inputLen, byte[] output) throws ShortBufferException {
        return gcm.update(input, inputOffset, inputLen, output);
    }

    /**
     * Continues a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized), processing another data part.
     * 
     * @see Cipher#update(byte[], int, int, byte[], int)
     */
    public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        return gcm.update(input, inputOffset, inputLen, output, outputOffset);
    }

    /**
     * Continues a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized), processing another data part.
     * 
     * @see Cipher#update(ByteBuffer, ByteBuffer)
     */
    public int update(ByteBuffer input, ByteBuffer output) throws ShortBufferException {
        return gcm.update(input, output);
    }

    /**
     * Continues a multi-part update of the Additional Authentication Data (AAD).
     * 
     * @see Cipher#updateAAD(byte[])
     */
    public void updateAAD(byte[] src) {
        gcm.updateAAD(src);
    }

    /**
     * Continues a multi-part update of the Additional Authentication Data (AAD).
     * 
     * @see Cipher#updateAAD(byte[], int, int)
     */
    public void updateAAD(byte[] src, int offset, int length) {
        gcm.updateAAD(src, offset, length);
    }

    /**
     * Continues a multi-part update of the Additional Authentication Data (AAD).
     * 
     * @see Cipher#updateAAD(ByteBuffer)
     */
    public void updateAAD(ByteBuffer src) {
        gcm.updateAAD(src);
    }

    /**
     * Wrap a key.
     * 
     * @see Cipher#wrap(Key)
     */
    public byte[] wrap(Key key) throws InvalidKeyException, IllegalBlockSizeException {
        return gcm.wrap(key);
    }
}
