/************************************************************************************
 This implementation of the ElGamal encryption scheme is based on the code from [1].

 This library is provided as-is and is covered by the MIT License [2] (except for the
 parts that belong to O'Reilly - they are covered by [3]).

 [1] Adam Freeman & Allen Jones, Programming .NET Security: O'Reilly Media, 2003,
     ISBN 9780596552275 (http://books.google.com.sg/books?id=ykXCNVOIEuQC)

 [2] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)

 [3] Tim O'Reilly, O'Reilly Policy on Re-Use of Code Examples from Books: website,
     2001, (http://www.oreillynet.com/pub/a/oreilly/ask_tim/2001/codepolicy.html)
 ************************************************************************************/
using System.Numerics;
using ElGamalExt.BigInt;

namespace ElGamalExt
{
    public struct ElGamalKeyStruct
    {
        public BigInteger P;
        public BigInteger G;
        public BigInteger Y;
        public BigInteger X;
        public ElGamalPaddingMode Padding; // this parameter should be considered part of the public key

        public int getPlaintextBlocksize()
        {
            return (P.BitCount() - 1) / 8;
        }

        public int getCiphertextBlocksize()
        {
            // We add 2 because last bit of a BigInteger is reserved to store its sign.
            // Therefore, theoretically, each part of ciphertext might need an extra byte to hold that one bit
            return ((P.BitCount() + 7) / 8) * 2 + 2;
        }
    }
}
