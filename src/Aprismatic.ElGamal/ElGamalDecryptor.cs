using System;
using System.Numerics;

namespace Aprismatic.ElGamal
{
    public class ElGamalDecryptor
    {
        private readonly ElGamalKeyStruct _keyStruct;

        public ElGamalDecryptor(ElGamalKeyStruct keyStruct)
        {
            _keyStruct = keyStruct;
        }

        public BigInteger ProcessByteBlock(ReadOnlySpan<byte> block_A, ReadOnlySpan<byte> block_B)
        {
            var A = new BigInteger(block_A);
            var B = new BigInteger(block_B);

            A = BigInteger.ModPow(A, _keyStruct.X, _keyStruct.P);
            A = A.ModInverse(_keyStruct.P);
            var M = B * A % _keyStruct.P;

            return M;
        }
    }
}
