package dev.salusa.crypto;

import static dev.salusa.crypto.InternalUtils.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.ArrayList;
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
        SecretKeySpec key = new SecretKeySpec(decodeHex("27ece6764c77eb17e28a4031878198f37ce95207205fba8671390c8d7449dc91"), "SequenceMac");
        SequenceMac mac = SequenceMac.getInstance(key, SequenceFunctionSpec.SHA256, decodeHex("00000000"));
        mac.update(decodeHex("74aee83f30db3fd88d6e31ad41710cb8d9a5dd01aad1d1"));
        mac.update(decodeHex("f1ed6e58d442903e34571544a8af4f49e86790417916f538746911edbbd34fb9"));
        mac.update(decodeHex("bd121635c5c732"));
        byte[] actual = mac.doFinal();
        assertHexEquals(actual, "484ad123ab6f1fea03ac9ae765a38bd34128367f408eada7ff8c21b3cd8515c3");

    }
    
    // @Test 
    // public void temp() {
    //     // System.out.println();
    //     fail(System.getProperties().toString());
    // }

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
        TypeToken<List<KAT>> listType = new TypeToken<List<KAT>>() {}; 
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

    @ParameterizedTest(name ="{index}: {1}")
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
        // TODO: strengthen tests
        hash.update(kat.getInputs());
        byte[] actual = hash.doFinal();
        assertHexEquals(actual, kat.finalOutputHex);
    }

    @ParameterizedTest(name ="{index}: {1}")
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
            assertThrows(GeneralSecurityException.class, () -> SequenceMac.getInstance(kat.getKey(), fSpec, kat.getCustomizer()));
            return;
        } else {
            hash = SequenceMac.getInstance(kat.getKey(), spec, kat.getCustomizer());
        }
        // TODO: strengthen tests
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
     Tests to write
     - Generic error cases
     - multiple doFinal results in same result each time
     - Multiple customization strings with cloning
     - Cannot (partial)update after doFinal without reset
     - Cannot doFinal after partialUpdate     
     */
}
