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

namespace ElGamalExt
{
    public abstract class ElGamalAbstractCipher
    {
        protected int o_block_size;
        protected int o_plaintext_blocksize;
        protected int o_ciphertext_blocksize;
        protected ElGamalKeyStruct o_key_struct;

        public ElGamalAbstractCipher(ElGamalKeyStruct p_key_struct)
        {
            o_key_struct = p_key_struct;

            o_plaintext_blocksize = p_key_struct.getPlaintextBlocksize();
            o_ciphertext_blocksize = p_key_struct.getCiphertextBlocksize();

            o_block_size = o_plaintext_blocksize;
        }

        public BigInteger ProcessByte(byte[] p_data)
        {
            //var x_complete_blocks = p_data.Length / o_block_size + (p_data.Length % o_block_size > 0 ? 1 : 0);
            //x_complete_blocks = Math.Max(x_complete_blocks - 1, 0);

            //if (x_complete_blocks == 0)
            return ProcessFinalByte(p_data);

            //using (var x_stream = new MemoryStream())
            //{
            //    var x_block = new byte[o_block_size];

            //    // run through and process the complete blocks
            //    var i = 0;
            //    for (; i < x_complete_blocks; i++)
            //    {
            //        Array.Copy(p_data, i * o_block_size, x_block, 0, o_block_size);

            //        var x_result = ProcessDataBlock(x_block);

            //        x_stream.Write(x_result, 0, x_result.Length);
            //    }

            //    var x_final_block = new byte[p_data.Length - (x_complete_blocks * o_block_size)];
            //    Array.Copy(p_data, i * o_block_size, x_final_block, 0, x_final_block.Length);

            //    var x_final_result = ProcessFinalDataBlock(x_final_block);

            //    x_stream.Write(x_final_result, 0, x_final_result.Length);

            //    return x_stream.ToArray();
            //}
        }

        public byte[] ProcessBigInteger(BigInteger p_data)
        {
            //var x_complete_blocks = p_data.Length / o_block_size + (p_data.Length % o_block_size > 0 ? 1 : 0);
            //x_complete_blocks = Math.Max(x_complete_blocks - 1, 0);

            //if (x_complete_blocks == 0)
            return ProcessFinalBigInteger(p_data);

            //using (var x_stream = new MemoryStream())
            //{
            //    var x_block = new byte[o_block_size];

            //    // run through and process the complete blocks
            //    var i = 0;
            //    for (; i < x_complete_blocks; i++)
            //    {
            //        Array.Copy(p_data, i * o_block_size, x_block, 0, o_block_size);

            //        var x_result = ProcessDataBlock(x_block);

            //        x_stream.Write(x_result, 0, x_result.Length);
            //    }

            //    var x_final_block = new byte[p_data.Length - (x_complete_blocks * o_block_size)];
            //    Array.Copy(p_data, i * o_block_size, x_final_block, 0, x_final_block.Length);

            //    var x_final_result = ProcessFinalDataBlock(x_final_block);

            //    x_stream.Write(x_final_result, 0, x_final_result.Length);

            //    return x_stream.ToArray();
            //}
        }

        //protected abstract byte[] ProcessBlockBigInteger(BigInteger p_block);
        //protected abstract byte[] ProcessBlockByte(byte[] p_block);

        protected abstract byte[] ProcessFinalBigInteger(BigInteger p_final_block);
        protected abstract BigInteger ProcessFinalByte(byte[] p_final_block);
    }
}
