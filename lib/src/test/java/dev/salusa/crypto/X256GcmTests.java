package dev.salusa.crypto;

import static dev.salusa.crypto.TestUtils.assertHexEquals;
import static dev.salusa.crypto.TestUtils.HEX;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.junit.jupiter.api.Test;

public class X256GcmTests {
    @Test
    public void vector1() throws Exception {
        X256GcmKeySpec key = X256GcmKeySpec
                .getInstance(HEX.parseHex("0101010101010101010101010101010101010101010101010101010101010101"));
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

    @Test
    public void vector2() throws Exception {
        X256GcmKeySpec key = X256GcmKeySpec
                .getInstance(HEX.parseHex("0303030303030303030303030303030303030303030303030303030303030303"));
        X256Gcm xgcm = X256Gcm.getInstance();
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

    @Test
    public void accumulatedRandomized() throws Exception {
        final SHAKEDigest xof = new SHAKEDigest(128);
        final SHAKEDigest hash = new SHAKEDigest(128);
        X256Gcm xGcm = X256Gcm.getInstance();
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

            if (iter == 0) {
                System.out.format("%d:\t%s%n", iter, HEX.formatHex(rawKey));
            }
            X256GcmKeySpec key = X256GcmKeySpec.getInstance(rawKey);
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
    // TODO: Coverage tests
    // TODO: Different providers
    // TODO: Remember explicit provider configuration in Spec
}
