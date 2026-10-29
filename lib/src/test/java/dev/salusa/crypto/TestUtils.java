package dev.salusa.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HexFormat;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

class TestUtils {
    static final BouncyCastleProvider BC = new BouncyCastleProvider();
    static final HexFormat HEX = HexFormat.of();

    static void assertHexEquals(byte[] actual, String expected) {
        String actualString = HEX.formatHex(actual);
        assertEquals(expected, actualString);
    }

    static void assertHexEquals(byte[] actual, byte[] expected) {
        String actualString = HEX.formatHex(actual);
        String expectedString = HEX.formatHex(expected);
        assertEquals(expectedString, actualString);
    }

    private TestUtils() {}
}
