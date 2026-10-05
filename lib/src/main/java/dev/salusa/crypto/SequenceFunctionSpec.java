package dev.salusa.crypto;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;

public class SequenceFunctionSpec implements AlgorithmParameterSpec {
    public static final SequenceFunctionSpec SHA1 = SequenceFunctionSpec.jce("SHA-1", 64);
    public static final SequenceFunctionSpec SHA256 = SequenceFunctionSpec.jce("SHA-256", 64);
    public static final SequenceFunctionSpec SHA384 = SequenceFunctionSpec.jce("SHA-384", 128);
    public static final SequenceFunctionSpec SHA512 = SequenceFunctionSpec.jce("SHA-512", 128);
    public static final SequenceFunctionSpec SHA3_256 = SequenceFunctionSpec.jce("SHA3-256", 136);
    public static final SequenceFunctionSpec SHA3_384 = SequenceFunctionSpec.jce("SHA3-384", 104);
    public static final SequenceFunctionSpec SHA3_512 = SequenceFunctionSpec.jce("SHA3-512", 72);
    public static final SequenceFunctionSpec BLAKE2B_512 = SequenceFunctionSpec.jce("BLAKE2B-512", 128);
    public static final SequenceFunctionSpec BLAKE2S_256 = SequenceFunctionSpec.jce("BLAKE2S-256", 64);

    private final String hashName;
    private final int blockSize;
    private final ThrowingSupplier<MessageDigest, GeneralSecurityException> hashSupplier;

    public static SequenceFunctionSpec jce(String hashName, int blockSize) {
        return new SequenceFunctionSpec(hashName, blockSize, new JceSupplier(hashName, null, null));
    }

    public static SequenceFunctionSpec jce(String hashName, String providerName, int blockSize) {
        return new SequenceFunctionSpec(hashName, blockSize, new JceSupplier(hashName, providerName, null));
    }

    public static SequenceFunctionSpec jce(String hashName, Provider provider, int blockSize) {
        return new SequenceFunctionSpec(hashName, blockSize, new JceSupplier(hashName, null, provider));
    }

    public static SequenceFunctionSpec explicit(String hashName, int blockSize, MessageDigest hash) {
        return new SequenceFunctionSpec(hashName, blockSize, () -> hash);
    }

    public static SequenceFunctionSpec supplier(String hashName, int blockSize, ThrowingSupplier<MessageDigest, GeneralSecurityException> supplier) {
        return new SequenceFunctionSpec(hashName, blockSize, supplier);
    }

    private SequenceFunctionSpec(String hashName, int blockSize, ThrowingSupplier<MessageDigest, GeneralSecurityException> hashSupplier) {
        this.hashName = hashName;
        this.blockSize = blockSize;
        this.hashSupplier = hashSupplier;
    }

    public String getHashName() {
        return hashName;
    }

    public int getBlockSize() {
        return blockSize;
    }

    MessageDigest getHash() throws GeneralSecurityException {
        return hashSupplier.get();
    }

    private static class JceSupplier implements ThrowingSupplier<MessageDigest, GeneralSecurityException> {
        private final String hashName;
        private final String providerName;
        private final Provider provider;

        public JceSupplier(String hashName, String providerName, Provider provider) {
            this.hashName = hashName;
            this.providerName = providerName;
            this.provider = provider;
        }
        @Override
        public MessageDigest get() throws GeneralSecurityException {
            if (provider != null) {
                return MessageDigest.getInstance(hashName, provider);
            }
            if (providerName != null) {
                return MessageDigest.getInstance(hashName, providerName);
            }
            return MessageDigest.getInstance(hashName);
        }
        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((hashName == null) ? 0 : hashName.hashCode());
            result = prime * result + ((providerName == null) ? 0 : providerName.hashCode());
            result = prime * result + ((provider == null) ? 0 : provider.hashCode());
            return result;
        }
        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            JceSupplier other = (JceSupplier) obj;
            if (hashName == null) {
                if (other.hashName != null)
                    return false;
            } else if (!hashName.equals(other.hashName))
                return false;
            if (providerName == null) {
                if (other.providerName != null)
                    return false;
            } else if (!providerName.equals(other.providerName))
                return false;
            if (provider == null) {
                if (other.provider != null)
                    return false;
            } else if (!provider.equals(other.provider))
                return false;
            return true;
        }
        @Override
        public String toString() {
            return "JceSupplier [hashName=" + hashName + ", providerName=" + providerName + ", provider=" + provider
                    + "]";
        }

    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((hashName == null) ? 0 : hashName.hashCode());
        result = prime * result + blockSize;
        result = prime * result + ((hashSupplier == null) ? 0 : hashSupplier.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        SequenceFunctionSpec other = (SequenceFunctionSpec) obj;
        if (hashName == null) {
            if (other.hashName != null)
                return false;
        } else if (!hashName.equals(other.hashName))
            return false;
        if (blockSize != other.blockSize)
            return false;
        if (hashSupplier == null) {
            if (other.hashSupplier != null)
                return false;
        } else if (!hashSupplier.equals(other.hashSupplier))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "SequenceFunctionSpec [hashName=" + hashName + ", blockSize=" + blockSize + ", hashSupplier="
                + hashSupplier + "]";
    }
}
