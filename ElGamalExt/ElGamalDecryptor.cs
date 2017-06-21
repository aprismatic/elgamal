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
using System.Linq;
using System.Numerics;
using BigIntegerExt;

namespace ElGamalExt
{
    public class ElGamalDecryptor : ElGamalAbstractCipher
    {
        public ElGamalDecryptor(ElGamalKeyStruct p_struct)
            : base(p_struct)
        {
            o_block_size = o_ciphertext_blocksize;
        }

        protected override byte[] ProcessDataBlock(byte[] p_block)
        {
            // extract the byte arrays that represent A and B
            var byteLength = o_ciphertext_blocksize / 2;
            var x_a_bytes = new byte[byteLength];
            Array.Copy(p_block, 0, x_a_bytes, 0, x_a_bytes.Length);
            var x_b_bytes = new byte[byteLength];
            Array.Copy(p_block, p_block.Length - x_b_bytes.Length, x_b_bytes, 0, x_b_bytes.Length);

            var A = new BigInteger(x_a_bytes);
            var B = new BigInteger(x_b_bytes);

            A = BigInteger.ModPow(A, o_key_struct.X, o_key_struct.P);
            A = A.ModInverse(o_key_struct.P);
            var M = B * A % o_key_struct.P;

            var x_m_bytes = M.ToByteArray();

            // we may end up with results which are short some trailing zeros
            if (x_m_bytes.Length < o_plaintext_blocksize)
            {
                var x_full_result = new byte[o_plaintext_blocksize];
                Array.Copy(x_m_bytes, 0, x_full_result, 0, x_m_bytes.Length);
                x_m_bytes = x_full_result;
            }
            return x_m_bytes;
        }

        protected override byte[] ProcessFinalDataBlock(byte[] p_final_block)
        {
            return p_final_block.Length > 0 ? UnpadPlaintextBlock(ProcessDataBlock(p_final_block)) : new byte[0];
        }

        protected byte[] UnpadPlaintextBlock(byte[] p_block)
        {
            var x_res = new byte[0];

            switch (o_key_struct.Padding)
            {
                // removing all the leading zeros
                case ElGamalPaddingMode.LeadingZeros:
                    var i = 0;
                    for (; i < p_block.Length; i++)
                    {
                        if (p_block[i] != 0)
                            break;
                    }
                    x_res = p_block.Skip(i).ToArray();
                    break;

                // removing all the trailing zeros
                case ElGamalPaddingMode.TrailingZeros:
                    var j = p_block.Length - 1;
                    for (; j >= 0; j--)
                    {
                        if (p_block[j] != 0)
                            break;
                    }
                    x_res = p_block.Take(j + 1).ToArray();
                    break;

                case ElGamalPaddingMode.ANSIX923:
                    throw new NotImplementedException();
                    break;

                case ElGamalPaddingMode.BigIntegerPadding:
                    var k = p_block.Length - 1;
                    if (p_block[k] == 0xFF)
                    {
                        for (; k >= 0; k--)
                        {
                            if (p_block[k] == 0xFF) continue;
                            if ((p_block[k] & 0b1000_0000) == 0)
                                k++;
                            break;
                        }
                    }
                    else if (p_block[k] == 0)
                    {
                        for (; k >= 0; k--)
                        {
                            if (p_block[k] == 0) continue;
                            if ((p_block[k] & 0b1000_0000) != 0)
                                k++;
                            break;
                        }
                    }
                    x_res = p_block.Take(k + 1).ToArray(); // TODO: Consider rewriting without LINQ
                    break;

                // unlikely to happen
                default:
                    throw new ArgumentOutOfRangeException();
            }

            return x_res;
        }
    }
}
