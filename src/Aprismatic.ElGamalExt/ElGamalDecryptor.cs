using System;
using System.Numerics;

namespace Aprismatic.ElGamalExt
{
    public class ElGamalDecryptor : ElGamalAbstractCipher
    {
        public ElGamalDecryptor(ElGamalKeyStruct keyStruct)
            : base(keyStruct)
        { }

        public BigInteger ProcessByteBlock(byte[] block)
        {
            // extract the byte arrays that represent A and B
            var byteLength = CiphertextBlocksize / 2;
            var a_bytes = new byte[byteLength];
            Array.Copy(block, 0, a_bytes, 0, a_bytes.Length);
            var b_bytes = new byte[byteLength];
            Array.Copy(block, block.Length - b_bytes.Length, b_bytes, 0, b_bytes.Length);

            var A = new BigInteger(a_bytes);
            var B = new BigInteger(b_bytes);

            A = BigInteger.ModPow(A, KeyStruct.X, KeyStruct.P);
            A = A.ModInverse(KeyStruct.P);
            var M = B * A % KeyStruct.P;

            return Decode(M);
        }

        private BigInteger Decode(BigInteger origin)
        {
            origin = origin % (KeyStruct.MaxRawPlaintext + 1);
            if (origin > KeyStruct.MaxRawPlaintext / 2)
                return origin - KeyStruct.MaxRawPlaintext - 1;
            return origin;
        }
    }
}
