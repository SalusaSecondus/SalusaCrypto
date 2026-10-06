package dev.salusa.crypto;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Immutable specification for an instance of {@link SequenceFunction}.
 * Comes with prebuilt instances for the most common cases.
 */
public class SequenceFunctionSpec implements AlgorithmParameterSpec {
    /** SHA-1 */
    public static final SequenceFunctionSpec SHA1 = SequenceFunctionSpec.jce("SHA-1", 64);
    /** SHA-256 */
    public static final SequenceFunctionSpec SHA256 = SequenceFunctionSpec.jce("SHA-256", 64);
    /** SHA-384 */
    public static final SequenceFunctionSpec SHA384 = SequenceFunctionSpec.jce("SHA-384", 128);
    /** SHA-512 */
    public static final SequenceFunctionSpec SHA512 = SequenceFunctionSpec.jce("SHA-512", 128);
    /** SHA3-256 */
    public static final SequenceFunctionSpec SHA3_256 = SequenceFunctionSpec.jce("SHA3-256", 136);
    /** SHA3-384 */
    public static final SequenceFunctionSpec SHA3_384 = SequenceFunctionSpec.jce("SHA3-384", 104);
    /** SHA3-512 */
    public static final SequenceFunctionSpec SHA3_512 = SequenceFunctionSpec.jce("SHA3-512", 72);
    /** Blake2b with 512 bit output */
    public static final SequenceFunctionSpec BLAKE2B_512 = SequenceFunctionSpec.jce("BLAKE2B-512", 128);
    /** Blake2s with 256 bit output */
    public static final SequenceFunctionSpec BLAKE2S_256 = SequenceFunctionSpec.jce("BLAKE2S-256", 64);

    private final String hashName;
    private final int blockSize;
    private final ThrowingSupplier<MessageDigest, GeneralSecurityException> hashSupplier;

    /**
     * Creates an instance of {@link SequenceFunctionSpec} where the
     * {@link MessageDigest} is produced by calling
     * {@link MessageDigest#getInstance(String)} with {@code hashName}.
     * 
     * @param hashName  value to pass to {@link MessageDigest#getInstance(String)}
     * @param blockSize the underlying block-size of the hash function.
     *                  This is <em>not</em> the output size of the hash function.
     */
    public static SequenceFunctionSpec jce(String hashName, int blockSize) {
        return new SequenceFunctionSpec(hashName, blockSize, new JceSupplier(hashName, null, null));
    }

    /**
     * Creates an instance of {@link SequenceFunctionSpec} where the
     * {@link MessageDigest} is produced by calling
     * {@link MessageDigest#getInstance(String, String)} with {@code hashName} and
     * {@code providerName}.
     * 
     * @param hashName     value to pass to
     *                     {@link MessageDigest#getInstance(String, String)}
     * @param providerName value to pass to
     *                     {@link MessageDigest#getInstance(String, String)}
     * @param blockSize    the underlying block-size of the hash function.
     *                     This is <em>not</em> the output size of the hash
     *                     function.
     */
    public static SequenceFunctionSpec jce(String hashName, String providerName, int blockSize) {
        return new SequenceFunctionSpec(hashName, blockSize, new JceSupplier(hashName, providerName, null));
    }

    /**
     * Creates an instance of {@link SequenceFunctionSpec} where the
     * {@link MessageDigest} is produced by calling
     * {@link MessageDigest#getInstance(String, Provider)} with {@code hashName} and
     * {@code provider}.
     * 
     * @param hashName  value to pass to
     *                  {@link MessageDigest#getInstance(String, Provider)}
     * @param provider  value to pass to
     *                  {@link MessageDigest#getInstance(String, Provider)}
     * @param blockSize the underlying block-size of the hash function.
     *                  This is <em>not</em> the output size of the hash
     *                  function.
     */
    public static SequenceFunctionSpec jce(String hashName, Provider provider, int blockSize) {
        return new SequenceFunctionSpec(hashName, blockSize, new JceSupplier(hashName, null, provider));
    }

    /**
     * Creates an instance of {@link SequenceFunctionSpec} where the
     * {@link MessageDigest} returned by {@link #getHash()} is simply
     * {@code hash.clone()}.
     * 
     * <p>{@code hash} <em>MUST</em> be in a freshly initialized state.
     * 
     * @param hashName  value to pass to
     *                  {@link MessageDigest#getInstance(String, Provider)}
     * @param hash      value return from {@link #getHash()}
     * @param blockSize the underlying block-size of the hash function.
     *                  This is <em>not</em> the output size of the hash
     *                  function.
     */
    public static SequenceFunctionSpec cloned(String hashName, int blockSize, MessageDigest hash) {
        return new SequenceFunctionSpec(hashName, blockSize, new MdCloner(hash));
    }

    /**
     * Creates an instance of {@link SequenceFunctionSpec} where {@link #getHash()}
     * delegates directly to calling {@code supplier}.
     * <p>
     * {@code supplier} <em>MUST</em> return a new instance for every calls
     * 
     * @param hashName  value to pass to
     *                  {@link MessageDigest#getInstance(String, Provider)}
     * @param supplier  supplier for {@link #getHash()}
     * @param blockSize the underlying block-size of the hash function.
     *                  This is <em>not</em> the output size of the hash
     *                  function.
     */
    public static SequenceFunctionSpec supplier(String hashName, int blockSize,
            ThrowingSupplier<MessageDigest, GeneralSecurityException> supplier) {
        return new SequenceFunctionSpec(hashName, blockSize, supplier);
    }

    private SequenceFunctionSpec(String hashName, int blockSize,
            ThrowingSupplier<MessageDigest, GeneralSecurityException> hashSupplier) {
        this.hashName = hashName;
        this.blockSize = blockSize;
        this.hashSupplier = hashSupplier;
    }

    /**
     * Returns the hash name (as would be passed to
     * {@link MessageDigest#getInstance(String)}).
     */
    public String getHashName() {
        return hashName;
    }

    /**
     * Returns the underlying block-size of the hash function.
     * This is <em>not</em> the output size of the hash function.
     * See <a href="https://c2sp.org/sequencehash#block-size-guidance">SequenceHash:
     * Block-size Guidance</a>.
     */
    public int getBlockSize() {
        return blockSize;
    }

    /**
     * Returns an instance of the hash function for use by {@link SequenceFunction}.
     * 
     * @throws GeneralSecurityException if the return value cannot be constructed
     */
    MessageDigest getHash() throws GeneralSecurityException {
        return hashSupplier.get();
    }

    private static class MdCloner implements ThrowingSupplier<MessageDigest, GeneralSecurityException> {
        private final MessageDigest template;

        private MdCloner(MessageDigest template) {
            this.template = template;
        }

        @Override 
        public MessageDigest get() throws GeneralSecurityException {
            try {
                return (MessageDigest) template.clone();
            } catch (final CloneNotSupportedException ex) {
                throw new GeneralSecurityException("Clone must be supported", ex);
            }
        }
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
