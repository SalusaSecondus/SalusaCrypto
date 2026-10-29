package dev.salusa.crypto;

import static dev.salusa.crypto.TestUtils.assertHexEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static dev.salusa.crypto.TestUtils.BC;
import static dev.salusa.crypto.TestUtils.HEX;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.amazon.corretto.crypto.provider.InputBuffer.ByteBufferFunction;

public class X256GcmTests {
    private static final String ALG_NAME = "XAES-256-GCM";
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("providers")
    public void vector1(String name, Object specProvider, Object cipherProvider) throws Exception {
        X256GcmKeySpec key = buildSpec(
            HEX.parseHex("0101010101010101010101010101010101010101010101010101010101010101"),
            specProvider);
        X256Gcm xgcm = getInstance(cipherProvider);
        IvParameterSpec iv = new IvParameterSpec("ABCDEFGHIJKLMNOPQRSTUVWX".getBytes(StandardCharsets.UTF_8));
        byte[] plaintext = "XAES-256-GCM".getBytes(StandardCharsets.UTF_8);
        xgcm.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] actual = xgcm.doFinal(plaintext);

        assertHexEquals(actual, "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271");

        xgcm.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = xgcm.doFinal(actual);
        assertHexEquals(decrypted, plaintext);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("providers")
    public void vector2(String name, Object specProvider, Object cipherProvider) throws Exception {
        X256GcmKeySpec key = buildSpec(
            HEX.parseHex("0303030303030303030303030303030303030303030303030303030303030303"),
            specProvider);
        assertEquals(ALG_NAME, key.getAlgorithm());
        assertEquals("RAW", key.getFormat());
        assertHexEquals(key.getEncoded(), "0303030303030303030303030303030303030303030303030303030303030303");
        X256Gcm xgcm = getInstance(cipherProvider);
        assertEquals(ALG_NAME, xgcm.getAlgorithm());
        IvParameterSpec iv = new IvParameterSpec("ABCDEFGHIJKLMNOPQRSTUVWX".getBytes(StandardCharsets.UTF_8));
        byte[] plaintext = "XAES-256-GCM".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "c2sp.org/XAES-256-GCM".getBytes(StandardCharsets.UTF_8);
        xgcm.init(Cipher.ENCRYPT_MODE, key, iv);

        xgcm.updateAAD(aad);
        byte[] actual = xgcm.doFinal(plaintext);

        assertHexEquals(actual, "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d");

        xgcm.init(Cipher.DECRYPT_MODE, key, iv);
        xgcm.updateAAD(aad);
        byte[] decrypted = xgcm.doFinal(actual);
        assertHexEquals(decrypted, plaintext);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("providers")
    public void accumulatedRandomized(String name, Object specProvider, Object cipherProvider) throws Exception {
        final SHAKEDigest xof = new SHAKEDigest(128);
        final SHAKEDigest hash = new SHAKEDigest(128);
        byte[] rawKey = new byte[32];
        byte[] rawIv = new byte[24];
        byte[] tmpLen = new byte[1];

        for (int iter = 0; iter < 10_000; iter++) {
            xof.doOutput(rawKey, 0, 32);
            xof.doOutput(rawIv, 0, 24);

            xof.doOutput(tmpLen, 0, 1);
            int ptLength = Byte.toUnsignedInt(tmpLen[0]);
            byte[] plaintext = new byte[ptLength];
            xof.doOutput(plaintext, 0, ptLength);

            xof.doOutput(tmpLen, 0, 1);
            int aadLength = Byte.toUnsignedInt(tmpLen[0]);
            byte[] aad = new byte[aadLength];
            xof.doOutput(aad, 0, aadLength);

            X256GcmKeySpec key = buildSpec(rawKey, specProvider);
            X256Gcm xGcm = getInstance(cipherProvider);

            IvParameterSpec iv = new IvParameterSpec(rawIv);
            xGcm.init(Cipher.ENCRYPT_MODE, key, iv);
            xGcm.updateAAD(aad, 0, aadLength);
            byte[] ciphertext = xGcm.doFinal(plaintext, 0, ptLength);

            xGcm.init(Cipher.DECRYPT_MODE, key, iv);
            xGcm.updateAAD(aad, 0, aadLength);
            byte[] decrypted = xGcm.doFinal(ciphertext, 0, ciphertext.length);
            assertHexEquals(decrypted, plaintext);
            hash.update(ciphertext, 0, ciphertext.length);
        }
        byte[] output = new byte[32];
        hash.doFinal(output, 0);
        assertHexEquals(output, "e6b9edf2df6cec60c8cbd864e2211b597fb69a529160cd040d56c0c210081939");
    }

    private static X256GcmKeySpec buildSpec(byte[] rawKey, Object prov) throws GeneralSecurityException {
        if (prov == null) {
            return X256GcmKeySpec.getInstance(rawKey);
        }
        if (prov instanceof String s) {
            return X256GcmKeySpec.getInstance(rawKey, s);
        }
        if (prov instanceof Provider p) {
            return X256GcmKeySpec.getInstance(rawKey, p);
        }
        throw new IllegalArgumentException();
    }

    private static X256Gcm getInstance(Object prov) throws GeneralSecurityException {
        if (prov == null) {
            return X256Gcm.getInstance();
        }
        if (prov instanceof String s) {
            return X256Gcm.getInstance(s);
        }
        if (prov instanceof Provider p) {
            return X256Gcm.getInstance(p);
        }
        throw new IllegalArgumentException();
    }

    public static List<Arguments> providers() {
        final List<Object> providers = new ArrayList<>();
        providers.add(null);
        providers.add("SunJCE");
        providers.add("BC");
        providers.add(BC);

        final List<Arguments> result = new ArrayList<>();
        for (final Object p1 : providers) {
            for (final Object p2 : providers) {
                String name = String.format("(%s, %s)", p2Str(p1), p2Str(p2));
                result.add(Arguments.of(name, p1, p2));
            }
        }
        return result;
    }

    private static String p2Str(Object prov) {
        if (prov == null) {
            return "[null]";
        }
        if (prov instanceof String s) {
            return "s:" + s;
        }
        if (prov instanceof Provider p) {
            return "p:" + p;
        }
        throw new IllegalArgumentException();
    }
    
    @Test
    public void testKeyLengthChecks() {
        assertThrows(InvalidKeyException.class, () -> X256GcmKeySpec.getInstance(new byte[16]));
        assertThrows(InvalidKeyException.class, () -> X256GcmKeySpec.getInstance(new byte[16], "BC"));
        assertThrows(InvalidKeyException.class, () -> X256GcmKeySpec.getInstance(new byte[16], BC));
    }

    @Test
    public void offsetVector1() throws Exception {
        X256GcmKeySpec key = X256GcmKeySpec.getInstance(
            HEX.parseHex("ff0101010101010101010101010101010101010101010101010101010101010101ff"),
            1);
        assertHexEquals(key.getEncoded(), "0101010101010101010101010101010101010101010101010101010101010101");
        X256Gcm xgcm = X256Gcm.getInstance();
        IvParameterSpec iv = new IvParameterSpec("ABCDEFGHIJKLMNOPQRSTUVWX".getBytes(StandardCharsets.UTF_8));
        byte[] plaintext = "XAES-256-GCM".getBytes(StandardCharsets.UTF_8);
        xgcm.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] actual = xgcm.doFinal(plaintext);

        assertHexEquals(actual, "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271");

        xgcm.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = xgcm.doFinal(actual);
        assertHexEquals(decrypted, plaintext);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("providers")
    public void symmetricWrap(final String name, Object specProvider, Object cipherProvider) throws Exception {
        final X256GcmKeySpec key = randomKey(specProvider);
        final SecretKey aesKey = new SecretKeySpec(InternalUtils.randomBytes(32), "AES");
        final X256Gcm xgcm = getInstance(cipherProvider);
        xgcm.init(Cipher.WRAP_MODE, key);
        final byte[] iv = xgcm.getIV();
        final byte[] wrapped = xgcm.wrap(aesKey);
        xgcm.init(Cipher.UNWRAP_MODE, key, new IvParameterSpec(iv));
        final Key unwrapped = xgcm.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        assertInstanceOf(SecretKey.class, unwrapped);
        assertEquals(aesKey.getAlgorithm(), unwrapped.getAlgorithm());
        assertEquals(aesKey.getFormat(), unwrapped.getFormat());
        assertHexEquals(unwrapped.getEncoded(), aesKey.getEncoded());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("providers")
    public void asymmetricWrap(final String name, Object specProvider, Object cipherProvider) throws Exception {
        final X256GcmKeySpec key = randomKey(specProvider);
        final X256Gcm xgcm = getInstance(cipherProvider);

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        final KeyPair kp = kpg.genKeyPair();
        
        xgcm.init(Cipher.WRAP_MODE, key);
        byte[] iv = xgcm.getIV();
        byte[] wrapped = xgcm.wrap(kp.getPublic());
        xgcm.init(Cipher.UNWRAP_MODE, key, new IvParameterSpec(iv));
        Key unwrapped = xgcm.unwrap(wrapped, "EC", Cipher.PUBLIC_KEY);
        assertInstanceOf(ECPublicKey.class, unwrapped);
        assertEquals("EC", unwrapped.getAlgorithm());
        assertEquals(kp.getPublic().getFormat(), unwrapped.getFormat());
        assertEquals(unwrapped, kp.getPublic());

        xgcm.init(Cipher.WRAP_MODE, key);
        iv = xgcm.getIV();
        wrapped = xgcm.wrap(kp.getPrivate());
        xgcm.init(Cipher.UNWRAP_MODE, key, new IvParameterSpec(iv));
        unwrapped = xgcm.unwrap(wrapped, "EC", Cipher.PRIVATE_KEY);
        assertInstanceOf(ECPrivateKey.class, unwrapped);
        assertEquals("EC", unwrapped.getAlgorithm());
        assertEquals(kp.getPrivate().getFormat(), unwrapped.getFormat());
        assertEquals(unwrapped, kp.getPrivate());
    }

    private static X256GcmKeySpec randomKey(Object provider) throws GeneralSecurityException {
        return buildSpec(InternalUtils.randomBytes(32), provider);
    }

    public static List<Arguments> inputVariantParams() {
        final List<Arguments> results = new ArrayList<>();
        final boolean[] vals = {true, false};
        for (final boolean useBuffer: vals) {
            for (final boolean useDirect: vals) {
                if (!useBuffer && useDirect) {
                    continue;
                }
                for (final boolean readOnly: vals) {
                    if (!useBuffer && readOnly) {
                        continue;
                    }
                    for (final boolean offset: vals) {
                        results.add(Arguments.of(useBuffer, useDirect, readOnly, offset));
                    }
                }
            }
        }
        return results;
    }

    @ParameterizedTest(name = "UseBuffer: {0}, UseDirect: {1}, ReadOnly: {2}, Offset: {3}")
    @MethodSource("inputVariantParams")
    public void inputVariants(boolean useBuffer, boolean useDirect, boolean readOnly, boolean offset) throws Exception {
        X256GcmKeySpec key = X256GcmKeySpec.getInstance(
            HEX.parseHex("0303030303030303030303030303030303030303030303030303030303030303"));
        X256Gcm xgcm = X256Gcm.getInstance();
        IvParameterSpec iv = new IvParameterSpec("ABCDEFGHIJKLMNOPQRSTUVWX".getBytes(StandardCharsets.UTF_8));
        byte[] plaintext = "XAES-256-GCM".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "c2sp.org/XAES-256-GCM".getBytes(StandardCharsets.UTF_8);
        xgcm.init(Cipher.ENCRYPT_MODE, key, iv);

        if (useBuffer) {
            xgcm.updateAAD(buildBB(aad, useDirect, readOnly, offset));
        } else if (offset) {
            byte[] tmp = new byte[aad.length + 3];
            System.arraycopy(aad, 0, tmp, 1, aad.length);
            xgcm.updateAAD(tmp, 1, aad.length);
        } else {
            xgcm.updateAAD(aad);
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        if (useBuffer) {
            ByteBuffer output = ByteBuffer.allocate(xgcm.getOutputSize(plaintext.length));
            xgcm.update(buildBB(plaintext, useDirect, readOnly, offset), output);
            output.flip();
            byte[] tmp = new byte[output.remaining()];
            output.get(tmp);
            baos.write(tmp);
        } else if (offset) {
            byte[] input = new byte[plaintext.length + 3];
            System.arraycopy(plaintext, 0, input, 1, plaintext.length);
            byte[] output = new byte[xgcm.getOutputSize(plaintext.length) + 3];
            int outLen = xgcm.update(input, 1, plaintext.length, output, 1);
            baos.write(output, 1, outLen);
        } else {
            baos.write(xgcm.update(plaintext));
        }
        baos.write(xgcm.doFinal());
        byte[] actual = baos.toByteArray();
        baos.reset();

        assertHexEquals(actual, "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d");

        xgcm.init(Cipher.DECRYPT_MODE, key, iv);
        xgcm.updateAAD(aad);
        byte[] decrypted;
        if (useBuffer) {
            ByteBuffer ctBuff = buildBB(actual, useDirect, readOnly, offset);
            ByteBuffer output = useDirect ? ByteBuffer.allocateDirect(xgcm.getOutputSize(actual.length)) : ByteBuffer.allocate(xgcm.getOutputSize(actual.length));
            int outLen = xgcm.doFinal(ctBuff, output);
            output.flip();
            assertEquals(outLen, output.remaining());
            decrypted = new byte[outLen];
            output.get(decrypted);
        } else {
            byte[] tmp = new byte[xgcm.getOutputSize(actual.length) + 1];
            int outLen = xgcm.doFinal(actual, 0, actual.length, tmp, 1);
            decrypted = Arrays.copyOfRange(tmp, 1, 1 + outLen);
        }
        assertHexEquals(decrypted, plaintext);
    }

    private static  ByteBuffer buildBB(byte[] input, boolean useDirect, boolean readOnly, boolean offset) {
        int startOffset = offset ? 1 : 0;
        int capacity = offset ? input.length + startOffset + 2 : input.length;
        ByteBuffer result = useDirect ? ByteBuffer.allocateDirect(capacity) : ByteBuffer.allocate(capacity);
        result.position(startOffset);
        result.put(input);
        result.rewind();
        if (readOnly) {
            result = result.asReadOnlyBuffer();
        }
        result.position(startOffset);
        result.limit(startOffset + input.length);
        return result;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("providers")
    public void randomIvIsRandom(final String name, Object specProvider, Object cipherProvider) throws Exception {
        final X256GcmKeySpec key = randomKey(specProvider);
        final X256Gcm xgcm = getInstance(cipherProvider);

        xgcm.init(Cipher.ENCRYPT_MODE, key);
        final byte[] iv1 = xgcm.getIV();
        xgcm.init(Cipher.ENCRYPT_MODE, key);
        final byte[] iv2 = xgcm.getIV();

        assertEquals(24, iv1.length);
        assertEquals(24, iv2.length);
        assertFalse(Arrays.equals(iv1, iv2));
    }
    // TODO: Coverage tests
}
