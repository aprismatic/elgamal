# ElGamalExt
Extension for the .NET Framework cryptography subsystem, which introduces the [ElGamal public key cryptosystem](https://en.wikipedia.org/wiki/ElGamal_encryption) with support for homomorphic multiplication.
As of v1.0.0, the library was migrated from our [own implementation of big integer arithmetics](https://github.com/bazzilic/BigInteger) to `System.Numerics.BigInteger`, which was introduced in the later versions of .NET Framework.

This code is based on the code from [1] and is partially covered by O'Reilly Code Policy [2].

Licensing terms for this library are in development at this moment.
As of now, the library can be used as-is for non-commercial use with a condition of attribution (a link to this repository is sufficient).
For commercial use please contact us.

**NOTE**: This library did not go through a proper review of cryptography implementation, might contain critical bugs, and generally should **not be considered production ready** yet.

[1] Adam Freeman & Allen Jones, Programming .NET Security: O'Reilly Media, 2003, ISBN 9780596552275 (http://books.google.com.sg/books?id=ykXCNVOIEuQC)

[2] Tim O'Reilly, O'Reilly Policy on Re-Use of Code Examples from Books: website, 2001, (http://www.oreillynet.com/pub/a/oreilly/ask_tim/2001/codepolicy.html)
