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
import javax.crypto.ExemptionMechanism;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class X256Gcm {
    private static final int AES_BLOCK_LENGTH = 16;
    private static final byte[] M_BASE = HexFormat.of()
            .parseHex("0001580000000000000000000000000000025800000000000000000000000000");

    private final Cipher ecb;
    private final Cipher gcm;
    private IvParameterSpec iv;

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

    public static X256Gcm getInstance(String providerName)
            throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException {
        final Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding", providerName);
        final Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding", providerName);
        return new X256Gcm(ecb, gcm);
    }

    public static X256Gcm getInstance(Provider provider) throws NoSuchAlgorithmException, NoSuchPaddingException {
        final Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding", provider);
        final Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding", provider);
        return new X256Gcm(ecb, gcm);
    }

    private X256Gcm(final Cipher ecb, final Cipher gcm) {
        this.ecb = ecb;
        this.gcm = gcm;
    }

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

    public byte[] doFinal() throws IllegalBlockSizeException, BadPaddingException {
        return gcm.doFinal();
    }

    public byte[] doFinal(byte[] input) throws IllegalBlockSizeException, BadPaddingException {
        return gcm.doFinal(input);
    }

    public int doFinal(byte[] output, int outputOffset)
            throws IllegalBlockSizeException, ShortBufferException, BadPaddingException {
        return gcm.doFinal(output, outputOffset);
    }

    public byte[] doFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        return gcm.doFinal(input, inputOffset, inputLen);
    }

    public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return gcm.doFinal(input, inputOffset, inputLen, output);
    }

    public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return gcm.doFinal(input, inputOffset, inputLen, output, outputOffset);
    }

    public int doFinal(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return gcm.doFinal(input, output);
    }

    public String getAlgorithm() {
        return "XAES-256-GCM";
    }

    public int getBlockSize() {
        return gcm.getBlockSize();
    }

    public ExemptionMechanism getExemptionMechanism() {
        return gcm.getExemptionMechanism();
    }

    public byte[] getIV() {
        return iv.getIV();
    }

    public int getOutputSize(int inputLen) {
        return gcm.getOutputSize(inputLen);
    }

    public Provider getProvider() {
        return gcm.getProvider();
    }

    @Override
    public String toString() {
        return "X256Gcm from " + gcm.getProvider();
    }

    public Key unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        return gcm.unwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    }

    public byte[] update(byte[] input) {
        return gcm.update(input);
    }

    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        return gcm.update(input, inputOffset, inputLen);
    }

    public int update(byte[] input, int inputOffset, int inputLen, byte[] output) throws ShortBufferException {
        return gcm.update(input, inputOffset, inputLen, output);
    }

    public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        return gcm.update(input, inputOffset, inputLen, output, outputOffset);
    }

    public int update(ByteBuffer input, ByteBuffer output) throws ShortBufferException {
        return gcm.update(input, output);
    }

    public void updateAAD(byte[] src) {
        gcm.updateAAD(src);
    }

    public void updateAAD(byte[] src, int offset, int length) {
        gcm.updateAAD(src, offset, length);
    }

    public void updateAAD(ByteBuffer src) {
        gcm.updateAAD(src);
    }

    public byte[] wrap(Key key) throws InvalidKeyException, IllegalBlockSizeException {
        return gcm.wrap(key);
    }
}
