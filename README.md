# SalusaCrypto

This is a collection of zero dependency classes that are useful in cryptography.
Some will be implementing standards. Some are useful optimizations. And others are syntactic sugar to just make things easier.

Unless otherwise specified, everything in this package requires no dependencies beyond those provided by stock Java and will work with any JCA implementations.

If you want your Java cryptography to be much faster in general, I strongly recommend adopting the [Amazon Corretto Crypto Provider (ACCP)](https://github.com/corretto/amazon-corretto-crypto-provider/), a former project of mine. It really does make everything better.

## Implemented Specifications

- `SequenceHash` and `SequenceMac` from [c2sp.org/sequencehash](https://c2sp.org/sequencehash) are implemented in by [SequenceFunction](lib/src/main/java/dev/salusa/crypto/SequenceFunction.java). This implementation requires that `MessageDigest` is cloneable. (All standard JCA providers, including [ACCP] and [BouncyCastle] meet the requirements.).

[ACCP]: https://github.com/corretto/amazon-corretto-crypto-provider/
[BouncyCastle]: https://www.bouncycastle.org/