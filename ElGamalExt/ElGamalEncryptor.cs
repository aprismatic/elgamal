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
            } while (BigInteger.GreatestCommonDivisor(K, o_key_struct.P - 1) != 1);

            var A = BigInteger.ModPow(o_key_struct.G, K, o_key_struct.P);
            var B = BigInteger.ModPow(o_key_struct.Y, K, o_key_struct.P) * new BigInteger(p_block) % o_key_struct.P;

            var x_a_bytes = A.ToByteArray();
            var x_b_bytes = B.ToByteArray();

            // create an array to contain the ciphertext
            var x_result = new byte[o_ciphertext_blocksize + 2];

            Array.Copy(x_a_bytes, 0, x_result, 0, x_a_bytes.Length);
            Array.Copy(x_b_bytes, 0, x_result, x_result.Length / 2, x_b_bytes.Length);

            return x_result;
        }

        protected override byte[] ProcessFinalDataBlock(byte[] p_final_block)
        {
            return p_final_block.Length > 0 ? ProcessDataBlock(PadPlaintextBlock(p_final_block)) : new byte[0];
        }

        protected byte[] PadPlaintextBlock(byte[] p_block)
        {
            if (p_block.Length < o_block_size)
            {
                var x_padded = new byte[o_block_size];

                switch (o_key_struct.Padding)
                {
                    // trailing zeros
                    case ElGamalPaddingMode.TrailingZeros:
                        Array.Copy(p_block, 0, x_padded, 0, p_block.Length);
                        break;

                    case ElGamalPaddingMode.LeadingZeros:
                        Array.Copy(p_block, 0, x_padded, o_block_size - p_block.Length, p_block.Length);
                        break;

                    case ElGamalPaddingMode.ANSIX923:
                        throw new NotImplementedException();
                        break;

                    case ElGamalPaddingMode.BigIntegerPadding:
                        Array.Copy(p_block, 0, x_padded, 0, p_block.Length);
                        if ((p_block[p_block.Length - 1] & 0b1000_0000) == 1)
                        {
                            for (var i = p_block.Length; i < x_padded.Length; i++)
                            {
                                x_padded[i] = 0xFF;
                            }
                        }
                        break;

                    // unlikely to happen
                    default:
                        throw new ArgumentOutOfRangeException();
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
