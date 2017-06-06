﻿/************************************************************************************
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
using ElGamalExt.BigInt;

namespace ElGamalExt
{
    public class ElGamalDecryptor : ElGamalAbstractCipher
    {

        public ElGamalDecryptor(ElGamalKeyStruct p_struct)
            : base(p_struct)
        {
            // set the default block size to be ciphertext
            o_block_size = o_ciphertext_blocksize;
        }

        protected override byte[] ProcessDataBlock(byte[] p_block)
        {
            // extract the byte arrays that represent A and B
            var x_a_bytes = new byte[o_ciphertext_blocksize / 2];
            Array.Copy(p_block, 0, x_a_bytes, 0, x_a_bytes.Length);
            var x_b_bytes = new byte[o_ciphertext_blocksize / 2];
            Array.Copy(p_block, p_block.Length - x_b_bytes.Length, x_b_bytes, 0, x_b_bytes.Length);

            // create big integers from the byte arrays
            var A = new BigInteger(x_a_bytes);
            var B = new BigInteger(x_b_bytes);

            // calculate the value M
            A = A.modPow(o_key_struct.X, o_key_struct.P);
            A = A.modInverse(o_key_struct.P);
            var M = B * A % o_key_struct.P;

            // return the result - take care to ensure that we create
            // a result which is the correct length
            var x_m_bytes = M.getBytes();

            // we may end up with results which are short some leading
            // bytes - add these are required
            if (x_m_bytes.Length < o_plaintext_blocksize)
            {
                var x_full_result = new byte[o_plaintext_blocksize];
                Array.Copy(x_m_bytes, 0, x_full_result,
                    o_plaintext_blocksize - x_m_bytes.Length, x_m_bytes.Length);
                x_m_bytes = x_full_result;
            }
            return x_m_bytes;
        }

        protected override byte[] ProcessFinalDataBlock(byte[] p_final_block)
        {
            if (!(p_final_block.Length > 0))
            {
                return new byte[0];
            }

            return UnpadPlaintextBlock(ProcessDataBlock(p_final_block));
        }

        protected byte[] UnpadPlaintextBlock(byte[] p_block)
        {
            var x_res = new byte[0];

            switch (o_key_struct.Padding)
            {
                // removing all the leading zeros
                case ElGamalPaddingMode.LeadingZeros:
                    var i = 0;
                    for (; i < o_plaintext_blocksize; i++)
                    {
                        if (p_block[i] != 0)
                            break;
                    }
                    x_res = p_block.Skip(i).ToArray();
                    break;

                // we can't determine which bytes are padding and which are meaningful
                // thus we return the block as is
                case ElGamalPaddingMode.Zeros:
                    x_res = p_block;
                    break;

                case ElGamalPaddingMode.ANSIX923:
                    throw new NotImplementedException();

                // unlikely to happen
                default:
                    throw new ArgumentOutOfRangeException();
            }

            return x_res;
        }
    }
}
