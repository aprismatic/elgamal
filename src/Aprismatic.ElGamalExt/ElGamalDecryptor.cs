﻿using System;
using System.Numerics;

namespace Aprismatic.ElGamalExt
{
    public class ElGamalDecryptor
    {
        private readonly ElGamalKeyStruct _keyStruct;

        public ElGamalDecryptor(ElGamalKeyStruct keyStruct)
        {
            _keyStruct = keyStruct;
        }

        public BigInteger ProcessByteBlock(Span<byte> block_A, Span<byte> block_B)
        {
            var A = new BigInteger(block_A);
            var B = new BigInteger(block_B);

            A = BigInteger.ModPow(A, _keyStruct.X, _keyStruct.P);
            A = A.ModInverse(_keyStruct.P);
            var M = B * A % _keyStruct.P;

            return Decode(M);
        }

        public BigInteger Decode(BigInteger origin) // TODO: Add tests now that this method is public
        {
            origin %= _keyStruct.MaxRawPlaintext + BigInteger.One;
            if (origin > _keyStruct.MaxEncryptableValue)
                return origin - _keyStruct.MaxRawPlaintext - BigInteger.One;
            return origin;
        }
    }
}
