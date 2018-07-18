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

using System;
using System.IO;
using System.Numerics;

namespace ElGamalExtModified
{
    public abstract class ElGamalModifiedAbstractCipher
    {
        protected int o_block_size;
        protected int o_plaintext_blocksize;
        protected int o_ciphertext_blocksize;
        protected ElGamalModifiedKeyStruct o_key_struct;

        public ElGamalModifiedAbstractCipher(ElGamalModifiedKeyStruct p_key_struct)
        {
            o_key_struct = p_key_struct;

            o_plaintext_blocksize = p_key_struct.getPlaintextBlocksize();
            o_ciphertext_blocksize = p_key_struct.getCiphertextBlocksize();

            o_block_size = o_plaintext_blocksize;
        }

        public abstract byte[] ProcessFinalBigInteger(BigInteger p_final_block);
        public abstract BigInteger ProcessFinalByte(byte[] p_final_block);
    }
}
