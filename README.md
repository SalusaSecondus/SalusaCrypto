# SalusaCrypto

This is a collection of zero dependency classes that are useful in cryptography.
Some will be implementing standards. Some are useful optimizations. And others are syntactic sugar to just make things easier.

Unless otherwise specified, everything in this package requires no dependencies beyond those provided by stock Java and will work with any JCA implementations.

[Javadoc](https://salusasecondus.github.io/SalusaCrypto/dev/salusa/crypto/package-summary.html) is available and is updated to match the most recent release.

If you want your Java cryptography to be much faster in general, I strongly recommend adopting the [Amazon Corretto Crypto Provider (ACCP)](https://github.com/corretto/amazon-corretto-crypto-provider/), a former project of mine. It really does make everything better.

## Installation

I generally recommend only pinning the major version number so that you always get the most recent version of this library. If you have even halfway decent unit-tests, that will be sufficient for automatic upgrades of minor and patch versions.

### Maven

```xml
<dependency>
  <groupId>dev.salusa</groupId>
  <artifactId>crypto</artifactId>
  <version>[1.0, 2.0)</version>
</dependency>
```

### Gradle

```
implementation 'dev.salusa:crypto:1.+'
```

## Implemented Specifications

- `SequenceHash` and `SequenceMac` from [c2sp.org/sequencehash](https://c2sp.org/sequencehash) are implemented in by [SequenceFunction](lib/src/main/java/dev/salusa/crypto/SequenceFunction.java). This implementation requires that `MessageDigest` is cloneable. (All standard JCA providers, including [ACCP] and [BouncyCastle] meet the requirements.).

[ACCP]: https://github.com/corretto/amazon-corretto-crypto-provider/
[BouncyCastle]: https://www.bouncycastle.org/

## Utilities

- Throwing interfaces.  
  Sometimes we need the equivalent of a [Consumer](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/function/Consumer.html) or [Supplier](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/function/Supplier.html) or similar but the method might throw an Exception (or error). How to do this, especially in a way that is compatible with lambdas? I define some new interfaces to make this easier and will add them as I need them (or if people request).
  - [ThrowingConsumer](lib/src/main/java/dev/salusa/crypto/ThrowingConsumer.java)
  - [ThrowingSupplier](lib/src/main/java/dev/salusa/crypto/ThrowingSupplier.java)

## Disclaimer

This project is the brainchild of a single person and maintained by him in his spare time.
While he is a professional developer and cryptographic engineer (and thus actually qualified to implement cryptography), this is still just his personal work.

That said, how many of your (transitive) dependencies have a similar of support but are just less honest about it?