package dev.salusa.crypto;

import static dev.salusa.crypto.InternalUtils.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import dev.salusa.crypto.SequenceFunction.SequenceHash;
import dev.salusa.crypto.SequenceFunction.SequenceMac;

public class SequenceFunctionTests {
    @Test
    public void EncodeMSBFTests() {
        assertHexEquals(SequenceFunction.encodeMSBF(0), "00000000000000000000000000000000");
        assertHexEquals(SequenceFunction.encodeMSBF(1), "00000000000000000000000000000001");
        assertThrows(IllegalArgumentException.class, () -> SequenceFunction.encodeMSBF(-1));
    }

    @Test
    public void EncodeLSBFTests() {
        assertHexEquals(SequenceFunction.encodeLSBF(0), "00000000000000000000000000000000");
        assertHexEquals(SequenceFunction.encodeLSBF(1), "01000000000000000000000000000000");
        assertThrows(IllegalArgumentException.class, () -> SequenceFunction.encodeMSBF(-1));
    }

    @Test
    public void PadTests() {
        assertHexEquals(SequenceFunction.pad("".getBytes(StandardCharsets.UTF_8), 64),
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        assertHexEquals(SequenceFunction.pad("JJJ".getBytes(StandardCharsets.UTF_8), 64),
                "4a4a4a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        assertHexEquals(
                SequenceFunction.pad("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW"
                        .getBytes(StandardCharsets.UTF_8), 64),
                "57575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757");
        assertHexEquals(
                SequenceFunction.pad("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW"
                        .getBytes(StandardCharsets.UTF_8), 64),
                "5757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    }

    @Test
    public void EncodeTests() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        SequenceFunction.encode("".getBytes(StandardCharsets.UTF_8), baos::write);
        assertHexEquals(baos.toByteArray(), "00000000000000000000000000000000");
        baos.reset();

        SequenceFunction.encode("AAA".getBytes(StandardCharsets.UTF_8), baos::write);
        assertHexEquals(baos.toByteArray(), "41414103000000000000000000000000000000");
        baos.reset();

        SequenceFunction.encode("SEQUENCEHASH".getBytes(StandardCharsets.UTF_8), baos::write);
        assertHexEquals(baos.toByteArray(), "53455155454e4345484153480c000000000000000000000000000000");
    }

    @Test
    public void smokeSha256() {
        SequenceHash hash = SequenceFunction.buildSha256();
        hash.update(null, 0, 0);
        hash.update(decodeHex("01"));
        hash.update(decodeHex("0202"));
        hash.update(decodeHex("030303"));
        byte[] actual = hash.doFinal();
        assertHexEquals(actual, "fe550c163f7ce3e8f636ca8770333c4ce33a1d8424b4f383036d424929111144");
    }

    @Test
    public void smokeSha256Mac() {
        SecretKeySpec key = new SecretKeySpec(decodeHex("27ece6764c77eb17e28a4031878198f37ce95207205fba8671390c8d7449dc91"), "SequenceMac");
        SequenceMac mac = SequenceFunction.buildSha256Mac(key, decodeHex("00000000"));
        mac.update(decodeHex("74aee83f30db3fd88d6e31ad41710cb8d9a5dd01aad1d1"));
        mac.update(decodeHex("f1ed6e58d442903e34571544a8af4f49e86790417916f538746911edbbd34fb9"));
        mac.update(decodeHex("bd121635c5c732"));
        byte[] actual = mac.doFinal();
        assertHexEquals(actual, "484ad123ab6f1fea03ac9ae765a38bd34128367f408eada7ff8c21b3cd8515c3");

    }
    
    public static void assertHexEquals(byte[] actual, String expected) {
        String actualString = bytesToHex(actual);
        assertEquals(actualString, expected);
    }

    /*
     Tests to write
     - Generic error cases
     - multiple doFinal results in same result each time
     - Multiple customization strings with cloning
     - Cannot (partial)update after doFinal without reset
     - Cannot doFinal after partialUpdate     
     */
}
