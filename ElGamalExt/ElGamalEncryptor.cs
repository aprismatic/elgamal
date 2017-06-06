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
using System.Numerics;
using System.Security.Cryptography;
using ElGamalExt.BigInt;

namespace ElGamalExt
{
    public class ElGamalEncryptor : ElGamalAbstractCipher, IDisposable
    {
        private RNGCryptoServiceProvider o_random;

        public ElGamalEncryptor(ElGamalKeyStruct p_struct)
            : base(p_struct)
        {
            o_random = new RNGCryptoServiceProvider();
        }

        protected override byte[] ProcessDataBlock(byte[] p_block)
        {
            // set random K
            BigInteger K;
            do
            {
                K = new BigInteger();
                K = K.genRandomBits(o_key_struct.P.bitCount() - 1, o_random);
            } while (K.gcd(o_key_struct.P - 1) != 1);

            // compute the values A and B
            var A = o_key_struct.G.modPow(K, o_key_struct.P);
            var B = o_key_struct.Y.modPow(K, o_key_struct.P) * new BigInteger(p_block) % o_key_struct.P;

            // copy the bytes from A and B into the result array
            var x_a_bytes = A.getBytes();

            // create an array to contain the ciphertext
            var x_result = new byte[o_ciphertext_blocksize];

            Array.Copy(x_a_bytes, 0, x_result, o_ciphertext_blocksize / 2
                - x_a_bytes.Length, x_a_bytes.Length);
            var x_b_bytes = B.getBytes();
            Array.Copy(x_b_bytes, 0, x_result, o_ciphertext_blocksize
                - x_b_bytes.Length, x_b_bytes.Length);
            // return the result array
            return x_result;
        }

        protected override byte[] ProcessFinalDataBlock(byte[] p_final_block)
        {
            if (!(p_final_block.Length > 0))
                return new byte[0];

            return ProcessDataBlock(PadPlaintextBlock(p_final_block));
        }

        protected byte[] PadPlaintextBlock(byte[] p_block)
        {
            if (p_block.Length < o_block_size)
            {
                var x_padded = new byte[o_block_size];

                switch (o_key_struct.Padding)
                {
                    // trailing zeros
                    case ElGamalPaddingMode.Zeros:
                        Array.Copy(p_block, 0, x_padded, 0, p_block.Length);
                        break;

                    case ElGamalPaddingMode.LeadingZeros:
                        Array.Copy(p_block, 0, x_padded, o_block_size - p_block.Length, p_block.Length);
                        break;

                    case ElGamalPaddingMode.ANSIX923:
                        throw new NotImplementedException();
                }

                return x_padded;
            }

            return p_block;
        }

        public void Dispose()
        {
            o_random.Dispose();
        }
    }
}
