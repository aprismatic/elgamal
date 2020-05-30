using System.Numerics;

namespace Aprismatic.ElGamalExt
{
    public struct ElGamalKeyStruct
    {
        public readonly BigInteger P;
        public readonly BigInteger G;
        public readonly BigInteger Y;
        public readonly BigInteger X;

        public ElGamalKeyStruct(BigInteger p, BigInteger g, BigInteger y, BigInteger x)
        {
            P = p;
            PBitCount = p.BitCount();
            PLength = (PBitCount + 7) >> 3; // div 8

            G = g;
            Y = y;
            X = x;

            CiphertextBlocksize = PLength * 2 + 2;      // We add 2 because last bit of a BigInteger is reserved to store its sign.
            CiphertextLength = CiphertextBlocksize * 2; // Therefore, theoretically, each part of ciphertext might need an extra byte to hold that one bit
        }

        public const int MaxPlaintextBits = 128;

        public static readonly BigInteger MaxRawPlaintext = BigInteger.Pow(2, MaxPlaintextBits) - BigInteger.One;
        public static readonly BigInteger MaxEncryptableValue = MaxRawPlaintext >> 1;

        public readonly int PBitCount;
        public readonly int PLength;

        public readonly int CiphertextBlocksize;
        public readonly int CiphertextLength;
    }
}
