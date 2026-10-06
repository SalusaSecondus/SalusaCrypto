# SalusaCrypto

This is a collection of zero dependency classes that are useful in cryptography.
Some will be implementing standards. Some are useful optimizations. And others are syntactic sugar to just make things easier.

Unless otherwise specified, everything in this package requires no dependencies beyond those provided by stock Java and will work with any JCA implementations.

If you want your Java cryptography to be much faster in general, I strongly recommend adopting the [Amazon Corretto Crypto Provider (ACCP)](https://github.com/corretto/amazon-corretto-crypto-provider/), a former project of mine. It really does make everything better.

## Implemented Specifications

- `SequenceHash` and `SequenceMac` from [c2sp.org/sequencehash](https://c2sp.org/sequencehash) are implemented in by [SequenceFunction](lib/src/main/java/dev/salusa/crypto/SequenceFunction.java). This implementation requires that `MessageDigest` is cloneable. (All standard JCA providers, including [ACCP] and [BouncyCastle] meet the requirements.).

[ACCP]: https://github.com/corretto/amazon-corretto-crypto-provider/
[BouncyCastle]: https://www.bouncycastle.org/

## Utilities

- Throwing interfaces.  
  Sometimes we need the equivalent of a [Consumer](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/function/Consumer.html) or [Supplier](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/function/Supplier.html) or similar but the method might throw an Exception (or error). How to do this, especially in a way that is compatible with lambdas? I define some new interfaces to make this easier and will add them as I need them (or if people request).
  - [ThrowingConsumer](lib/src/main/java/dev/salusa/crypto/ThrowingConsumer.java)
  - [ThrowingSupplier](lib/src/main/java/dev/salusa/crypto/ThrowingSupplier.java)