package dev.salusa.crypto;

import static dev.salusa.crypto.TestUtils.assertHexEquals;
import static dev.salusa.crypto.TestUtils.HEX;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.Test;

public class X256GcmTests {    
    @Test 
    public void vector1() throws Exception {
        X256GcmKeySpec key = X256GcmKeySpec.getInstance(HEX.parseHex("0101010101010101010101010101010101010101010101010101010101010101"));
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
        X256GcmKeySpec key = X256GcmKeySpec.getInstance(HEX.parseHex("0303030303030303030303030303030303030303030303030303030303030303"));
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
    // TODO: Coverage tests
    // TODO: Different providerds
}
