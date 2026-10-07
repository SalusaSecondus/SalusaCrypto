package dev.salusa.crypto;

import static dev.salusa.crypto.InternalUtils.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;

import dev.salusa.crypto.SequenceFunction.SequenceHash;
import dev.salusa.crypto.SequenceFunction.SequenceMac;

public class SequenceFunctionTests {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static List<Arguments> knownSpecs() {
        return Arrays.asList(
                Arguments.of(SequenceFunctionSpec.SHA1, SequenceFunctionSpec.SHA1.getHashName()),
                Arguments.of(SequenceFunctionSpec.SHA256, SequenceFunctionSpec.SHA256.getHashName()),
                Arguments.of(SequenceFunctionSpec.SHA384, SequenceFunctionSpec.SHA384.getHashName()),
                Arguments.of(SequenceFunctionSpec.SHA512, SequenceFunctionSpec.SHA512.getHashName()),
                Arguments.of(SequenceFunctionSpec.SHA3_256, SequenceFunctionSpec.SHA3_256.getHashName()),
                Arguments.of(SequenceFunctionSpec.SHA3_384, SequenceFunctionSpec.SHA3_384.getHashName()),
                Arguments.of(SequenceFunctionSpec.SHA3_512, SequenceFunctionSpec.SHA3_512.getHashName()),
                Arguments.of(SequenceFunctionSpec.BLAKE2B_512, SequenceFunctionSpec.BLAKE2B_512.getHashName()),
                Arguments.of(SequenceFunctionSpec.BLAKE2S_256, SequenceFunctionSpec.BLAKE2S_256.getHashName()));
    }

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
    public void smokeSha256() throws Exception {
        SequenceHash hash = SequenceHash.getInstance(SequenceFunctionSpec.SHA256);
        hash.update(null, 0, 0);
        hash.update(decodeHex("01"));
        hash.update(decodeHex("0202"));
        hash.update(decodeHex("030303"));
        byte[] actual = hash.doFinal();
        assertHexEquals(actual, "fe550c163f7ce3e8f636ca8770333c4ce33a1d8424b4f383036d424929111144");
    }

    @Test
    public void smokeSha256Mac() throws GeneralSecurityException {
        SecretKeySpec key = new SecretKeySpec(
                decodeHex("27ece6764c77eb17e28a4031878198f37ce95207205fba8671390c8d7449dc91"), "SequenceMac");
        SequenceMac mac = SequenceMac.getInstance(key, SequenceFunctionSpec.SHA256, decodeHex("00000000"));
        mac.update(decodeHex("74aee83f30db3fd88d6e31ad41710cb8d9a5dd01aad1d1"));
        mac.update(decodeHex("f1ed6e58d442903e34571544a8af4f49e86790417916f538746911edbbd34fb9"));
        mac.update(decodeHex("bd121635c5c732"));
        byte[] actual = mac.doFinal();
        assertHexEquals(actual, "484ad123ab6f1fea03ac9ae765a38bd34128367f408eada7ff8c21b3cd8515c3");

    }

    @Test
    public void arrays() throws Exception {
        SequenceHash hash = SequenceHash.getInstance(SequenceFunctionSpec.SHA256);
        hash.update(new byte[0],
                decodeHex("01"),
                decodeHex("0202"),
                decodeHex("030303"));
        byte[] actual = hash.doFinal();
        assertHexEquals(actual, "fe550c163f7ce3e8f636ca8770333c4ce33a1d8424b4f383036d424929111144");
    }

    @Test
    public void byteBufferArrayTests() throws Exception {
        ByteBuffer i0 = ByteBuffer.allocate(0);
        ByteBuffer i1 = ByteBuffer.wrap(decodeHex("01"));
        ByteBuffer i2 = ByteBuffer.wrap(decodeHex("0202")).asReadOnlyBuffer();
        ByteBuffer i3 = ByteBuffer.allocate(10);
        i3.position(2);
        i3.put(decodeHex("030303"));
        i3.limit(i3.position());
        i3.position(2);
        assertEquals(3, i3.remaining());

        SequenceHash hash = SequenceHash.getInstance(SequenceFunctionSpec.SHA256);
        hash.update(i0);
        hash.update(i1);
        hash.update(i2);
        hash.update(i3);
        byte[] actual = hash.doFinal();
        assertHexEquals(actual, "fe550c163f7ce3e8f636ca8770333c4ce33a1d8424b4f383036d424929111144");
        assertEquals(0, i0.remaining());
        assertEquals(0, i1.remaining());
        assertEquals(0, i2.remaining());
        assertEquals(0, i3.remaining());
    }

    @Test
    public void byteBufferDirectTests() throws Exception {
        ByteBuffer i0 = ByteBuffer.allocateDirect(0);
        ByteBuffer i1 = ByteBuffer.allocateDirect(1);
        i1.put(decodeHex("01"));
        i1.flip();
        ByteBuffer i2 = ByteBuffer.allocateDirect(2);
        i2.put(decodeHex("0202"));
        i2.flip();
        i2 = i2.asReadOnlyBuffer();
        ByteBuffer i3 = ByteBuffer.allocateDirect(10);
        i3.position(2);
        i3.put(decodeHex("030303"));
        i3.limit(i3.position());
        i3.position(2);
        assertEquals(3, i3.remaining());

        SequenceHash hash = SequenceHash.getInstance(SequenceFunctionSpec.SHA256);
        hash.update(i0);
        hash.update(i1);
        hash.update(i2);
        hash.update(i3);
        byte[] actual = hash.doFinal();
        assertHexEquals(actual, "fe550c163f7ce3e8f636ca8770333c4ce33a1d8424b4f383036d424929111144");
        assertEquals(0, i0.remaining());
        assertEquals(0, i1.remaining());
        assertEquals(0, i2.remaining());
        assertEquals(0, i3.remaining());
    }

    @Test
    public void byteBuffers() throws Exception {
        ByteBuffer i0 = ByteBuffer.allocate(0);
        ByteBuffer i1 = ByteBuffer.wrap(decodeHex("01"));
        ByteBuffer i2 = ByteBuffer.wrap(decodeHex("0202")).asReadOnlyBuffer();
        ByteBuffer i3 = ByteBuffer.allocate(10);
        i3.position(2);
        i3.put(decodeHex("030303"));
        i3.limit(i3.position());
        i3.position(2);
        assertEquals(3, i3.remaining());

        SequenceHash hash = SequenceHash.getInstance(SequenceFunctionSpec.SHA256);
        hash.update(i0,
                i1,
                i2,
                i3);
        byte[] actual = hash.doFinal();
        assertHexEquals(actual, "fe550c163f7ce3e8f636ca8770333c4ce33a1d8424b4f383036d424929111144");
        assertEquals(0, i0.remaining());
        assertEquals(0, i1.remaining());
        assertEquals(0, i2.remaining());
        assertEquals(0, i3.remaining());
    }

    @Test
    public void mixedIterable() throws Exception {
        byte[] i0 = new byte[0];
        ByteBuffer i1 = ByteBuffer.wrap(decodeHex("01"));
        ByteBuffer i2 = ByteBuffer.allocateDirect(2);
        i2.put(decodeHex("0202"));
        i2.flip();
        i2 = i2.asReadOnlyBuffer();
        byte[] i3 = decodeHex("030303");
        List<Object> inputs = Arrays.asList(i0, i1, i2, i3);

        SequenceHash hash = SequenceHash.getInstance(SequenceFunctionSpec.SHA256);
        hash.update(inputs);
        byte[] actual = hash.doFinal();
        assertHexEquals(actual, "fe550c163f7ce3e8f636ca8770333c4ce33a1d8424b4f383036d424929111144");
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("knownSpecs")
    public void doFinalRepeats(SequenceFunctionSpec spec, String name) throws GeneralSecurityException {
        byte[] customizationString = "Hello World".getBytes(StandardCharsets.UTF_8);
        SequenceHash hash = SequenceHash.getInstance(spec, customizationString);

        byte[] val1 = new byte[] { (byte) 1, 2, 3, 4 };
        byte[] val2 = new byte[] { (byte) 1, 2, 3, 4 };
        hash.update(val1);
        hash.update(val2);
        byte[] expected = hash.doFinal();
        byte[] actual = hash.doFinal();
        assertHexEquals(actual, expected);

        // We should also be able to clone it and get the same answer
        SequenceHash hash2 = hash.clone();
        actual = hash2.doFinal();
        assertHexEquals(actual, expected);

        // Cloning with the same customization string doesn't change anything
        hash2 = hash.cloneWithCustomization(customizationString);
        actual = hash2.doFinal();
        assertHexEquals(actual, expected);

        // Also test that we cannot update after a dofinal without a reset
        assertThrows(IllegalStateException.class, () -> hash.update(val1));
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("knownSpecs")
    public void cloneWithCustomization(SequenceFunctionSpec spec, String name) throws Exception {
        byte[] customizationString1 = "Hello World".getBytes(StandardCharsets.UTF_8);
        byte[] customizationString2 = "Goodbye World".getBytes(StandardCharsets.UTF_8);

        SequenceHash hash1 = SequenceHash.getInstance(spec, customizationString1);
        SequenceHash hash2 = SequenceHash.getInstance(spec, customizationString2);

        byte[] val1 = new byte[] { (byte) 1, 2, 3, 4 };
        byte[] val2 = new byte[] { (byte) 1, 2, 3, 4 };

        hash1.update(val1);
        hash1.update(val2);
        byte[] expected1 = hash1.doFinal();

        hash2.update(val1);
        hash2.update(val2);
        byte[] expected2 = hash2.doFinal();

        SequenceHash cloned2 = hash1.cloneWithCustomization(customizationString2);
        byte[] actual2 = cloned2.doFinal();

        assertHexEquals(actual2, expected2);

        hash1.reset();
        hash1.update(val1);
        hash1.update(val2);
        byte[] actual1 = hash1.doFinal();

        assertHexEquals(actual1, expected1);

        cloned2.reset();
        cloned2.update(val1);
        cloned2.update(val2);
        actual2 = cloned2.doFinal();
        assertHexEquals(actual2, expected2);
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("knownSpecs")
    public void partialByteArrays(SequenceFunctionSpec spec, String name) throws GeneralSecurityException {
        SequenceHash hash = SequenceHash.getInstance(spec);
        byte[] val1 = new byte[] { (byte) 1, 2, 3, 4 };
        byte[] val2 = new byte[] { (byte) 4, 2, 3, 1 };
        hash.update(val1);
        hash.update(val2);
        byte[] expected = hash.doFinal();
        hash.reset();
        assertFalse(hash.partialInputProcessed());
        hash.updatePartial(val1, 0, 1);
        assertTrue(hash.partialInputProcessed());
        hash.updatePartial(val1, 1, 2);
        assertTrue(hash.partialInputProcessed());
        hash.update(val1, 3, 1);
        assertFalse(hash.partialInputProcessed());
        hash.updatePartial(val2, 0, 2);
        assertTrue(hash.partialInputProcessed());
        hash.update(val2, 2, 2);
        assertFalse(hash.partialInputProcessed());
        byte[] actual = hash.doFinal();
        assertFalse(hash.partialInputProcessed());
        assertHexEquals(actual, expected);
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("knownSpecs")
    public void partialBuffers(SequenceFunctionSpec spec, String name) throws GeneralSecurityException {
        SequenceHash hash = SequenceHash.getInstance(spec);
        ByteBuffer val1 = ByteBuffer.wrap(new byte[] { (byte) 1, 2, 3, 4 });
        ByteBuffer val2 = ByteBuffer.wrap(new byte[] { (byte) 4, 2, 3, 1 });

        hash.update(val1.duplicate());
        hash.update(val2.duplicate());
        byte[] expected = hash.doFinal();
        hash.reset();
        assertFalse(hash.partialInputProcessed());
        hash.updatePartial(val1.duplicate().limit(2));
        assertTrue(hash.partialInputProcessed());
        hash.update(val1.duplicate().position(2));
        assertFalse(hash.partialInputProcessed());
        hash.updatePartial(val2.duplicate().limit(1));
        assertTrue(hash.partialInputProcessed());
        hash.updatePartial(val2.duplicate().position(1).limit(3));
        assertTrue(hash.partialInputProcessed());
        hash.update(val2.duplicate().position(3));
        assertFalse(hash.partialInputProcessed());
        byte[] actual = hash.doFinal();
        assertFalse(hash.partialInputProcessed());
        assertHexEquals(actual, expected);
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("knownSpecs")
    public void outputLengths(SequenceFunctionSpec spec, String name) throws Exception {
        MessageDigest md = MessageDigest.getInstance(spec.getHashName());
        SequenceHash hash = SequenceFunction.getHash(spec);
        assertEquals(md.getDigestLength(), hash.getOutputLength());
    }

    public static void assertHexEquals(byte[] actual, byte[] expected) {
        String actualString = bytesToHex(actual);
        String expectedString = bytesToHex(expected);
        assertEquals(expectedString, actualString);
    }

    public static void assertHexEquals(byte[] actual, String expected) {
        String actualString = bytesToHex(actual);
        assertEquals(expected, actualString);
    }

    public static List<Arguments> buildHashKats() throws Exception {
        return buildKats("hash");
    }

    public static List<Arguments> buildMacKats() throws Exception {
        return buildKats("mac");
    }

    private static List<Arguments> buildKats(String subdir) throws Exception {
        Gson gson = new GsonBuilder()
                .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                .disableJdkUnsafe()
                .create();
        Path katsDir;
        if (System.getenv("CCTV_KATS_PATH") != null) {
            katsDir = Paths.get(System.getenv("CCTV_KATS_PATH"), subdir);
        } else {
            katsDir = Paths.get("CCTV", "sequencehash", subdir);
        }
        List<Arguments> result = new ArrayList<>();
        TypeToken<List<KAT>> listType = new TypeToken<List<KAT>>() {
        };
        for (Path file : Files.list(katsDir).collect(Collectors.toList())) {
            if (Files.isDirectory(file)) {
                continue;
            }
            String content = Files.readString(file);
            List<KAT> kats = gson.fromJson(content, listType);
            for (KAT k : kats) {
                result.add(Arguments.of(k, k.toString()));
            }
        }
        return result;
    }

    @ParameterizedTest(name = "{index}: {1}")
    @MethodSource("buildHashKats")
    public void testHashKats(KAT kat, String name) throws Exception {
        assumeFalse(kat.mustFail, "MustFail not supported yet");

        SequenceFunctionSpec spec = null;
        switch (kat.hashName) {
            case "sha1":
                spec = SequenceFunctionSpec.SHA1;
                break;
            case "sha256":
                spec = SequenceFunctionSpec.SHA256;
                break;
            case "sha384":
                spec = SequenceFunctionSpec.SHA384;
                break;
            case "sha512":
                spec = SequenceFunctionSpec.SHA512;
                break;
            case "sha3_256":
                spec = SequenceFunctionSpec.SHA3_256;
                break;
            case "sha3_384":
                spec = SequenceFunctionSpec.SHA3_384;
                break;
            case "sha3_512":
                spec = SequenceFunctionSpec.SHA3_512;
                break;
            case "blake2b":
                spec = SequenceFunctionSpec.BLAKE2B_512;
                break;
            case "blake2s":
                spec = SequenceFunctionSpec.BLAKE2S_256;
                break;
            default:
                Assumptions.abort("Unsupported hash function: " + kat.hashName);
                break;
        }
        SequenceHash hash = SequenceHash.getInstance(spec, kat.getCustomizer());
        hash.update(kat.getInputs());
        byte[] actual = hash.doFinal();
        assertHexEquals(actual, kat.finalOutputHex);
    }

    @ParameterizedTest(name = "{index}: {1}")
    @MethodSource("buildMacKats")
    public void testMacKats(KAT kat, String name) throws Exception {
        SequenceFunctionSpec spec = null;
        switch (kat.hashName) {
            case "sha1":
                spec = SequenceFunctionSpec.SHA1;
                break;
            case "sha256":
                spec = SequenceFunctionSpec.SHA256;
                break;
            case "sha384":
                spec = SequenceFunctionSpec.SHA384;
                break;
            case "sha512":
                spec = SequenceFunctionSpec.SHA512;
                break;
            case "sha3_256":
                spec = SequenceFunctionSpec.SHA3_256;
                break;
            case "sha3_384":
                spec = SequenceFunctionSpec.SHA3_384;
                break;
            case "sha3_512":
                spec = SequenceFunctionSpec.SHA3_512;
                break;
            case "blake2b":
                spec = SequenceFunctionSpec.BLAKE2B_512;
                break;
            case "blake2s":
                spec = SequenceFunctionSpec.BLAKE2S_256;
                break;
            default:
                Assumptions.abort("Unsupported hash function: " + kat.hashName);
                break;
        }
        SequenceMac hash;
        if (kat.mustFail) {
            final SequenceFunctionSpec fSpec = spec;
            assertThrows(GeneralSecurityException.class,
                    () -> SequenceMac.getInstance(kat.getKey(), fSpec, kat.getCustomizer()));
            return;
        } else {
            hash = SequenceMac.getInstance(kat.getKey(), spec, kat.getCustomizer());
        }
        hash.update(kat.getInputs());
        byte[] actual = hash.doFinal();
        assertHexEquals(actual, kat.finalOutputHex);
    }

    public static final class KAT {
        public String hashName;
        public int functionId;
        @SerializedName("key")
        public String keyHex;
        @SerializedName("customizer")
        public String customizerHex;
        @SerializedName("inputs")
        public List<String> inputsHex;
        public boolean mayFail;
        public boolean mayWarn;
        public boolean mustFail;
        @SerializedName("final_output")
        public String finalOutputHex;
        @SerializedName("inner_hash")
        public String innerHashHex;
        @SerializedName("inner_header")
        public String innerHeaderHex;
        @SerializedName("outer_header")
        public String outerHeaderHex;

        public SecretKeySpec getKey() {
            return new SecretKeySpec(decodeHex(keyHex), "SequenceMac");
        }

        public byte[] getCustomizer() {
            return decodeHex(customizerHex);
        }

        public List<byte[]> getInputs() {
            return inputsHex.stream().map(InternalUtils::decodeHex).collect(Collectors.toList());
        }

        @Override
        public String toString() {
            return String.format("[%s] %d (%s) -> %s", hashName, functionId, keyHex, finalOutputHex);
        }
    }
    /*
     * Tests to write
     * - Generic error cases
     * - Cannot (partial)update after doFinal without reset
     * - Cannot doFinal after partialUpdate
     */
}
