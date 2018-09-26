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
		private static readonly BigInteger max = new BigInteger(UInt64.MaxValue);

		public ElGamalDecryptor(ElGamalKeyStruct p_struct)
            : base(p_struct)
        {
            o_block_size = o_ciphertext_blocksize;
        }

        public BigInteger ProcessByteBlock(byte[] p__block)
        {

            // extract the byte arrays that represent A and B
            var byteLength = o_ciphertext_blocksize / 2;
            var x_a_bytes = new byte[byteLength];
            Array.Copy(p__block, 0, x_a_bytes, 0, x_a_bytes.Length);
            var x_b_bytes = new byte[byteLength];
            Array.Copy(p__block, p__block.Length - x_b_bytes.Length, x_b_bytes, 0, x_b_bytes.Length);

            var A = new BigInteger(x_a_bytes);
            var B = new BigInteger(x_b_bytes);

            A = BigInteger.ModPow(A, o_key_struct.X, o_key_struct.P);
            A = A.ModInverse(o_key_struct.P);
            var M = B * A % o_key_struct.P;

            // we may end up with results which are short some trailing zeros
            return Decode(M);
        }

		private BigInteger Decode(BigInteger origin)
		{
			origin = origin % (max + 1);
			if (origin > max / 2)
				return origin - max - 1;
			return origin;
		}
    }
}
