/************************************************************************************
 This implementation of the ElGamal encryption scheme is based on the code from [1].
 It was changed and extended by Vasily Sidorov (http://bazzilic.me/).
 
 This code is provided as-is and is covered by the WTFPL 2.0 [2] (except for the
 parts that belong by O'Reilly - they are covered by [3]).
 
 
 [1] Adam Freeman & Allen Jones, Programming .NET Security: O'Reilly Media, 2003,
     ISBN 9780596552275 (http://books.google.com.sg/books?id=ykXCNVOIEuQC)
 
 [2] WTFPL – Do What the Fuck You Want to Public License, website,
     (http://wtfpl.net/)
 
 [3] Tim O'Reilly, O'Reilly Policy on Re-Use of Code Examples from Books: website,
     2001, (http://www.oreillynet.com/pub/a/oreilly/ask_tim/2001/codepolicy.html)
 ************************************************************************************/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ElGamalExt
{
    public class ElGamalEncryptor : ElGamalAbstractCipher
    {
        Random o_random;

        public ElGamalEncryptor(ElGamalKeyStruct p_struct)
            : base(p_struct)
        {
            o_random = new Random();
        }

        protected override byte[] ProcessDataBlock(byte[] p_block)
        {
            // set random K
            BigInteger K;            
            do
            {
                K = new BigInteger();
                K.genRandomBits(o_key_struct.P.bitCount() - 1, o_random);
            } while (K.gcd(o_key_struct.P - 1) != 1);

            // compute the values A and B
            BigInteger A =  o_key_struct.G.modPow(K, o_key_struct.P);
            BigInteger B = (o_key_struct.Y.modPow(K, o_key_struct.P) * new BigInteger(p_block)) % (o_key_struct.P);

            // create an array to contain the ciphertext
            byte[] x_result = new byte[o_ciphertext_blocksize];
            // copy the bytes from A and B into the result array
            byte[] x_a_bytes = A.getBytes();
            Array.Copy(x_a_bytes, 0, x_result, o_ciphertext_blocksize / 2
                - x_a_bytes.Length, x_a_bytes.Length);
            byte[] x_b_bytes = B.getBytes();
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
                byte[] x_padded = new byte[o_block_size];

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
                        throw new System.NotImplementedException();
                        break;
                }

                return x_padded;
            }

            return p_block;
        }
    }
}
