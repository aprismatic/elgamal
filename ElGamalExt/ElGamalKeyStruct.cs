using BigIntegerExt;
using System;
using System.Numerics;

namespace ElGamalExt
{
    public struct ElGamalKeyStruct
    {
        public BigInteger P;
        public BigInteger G;
        public BigInteger Y;
        public BigInteger X;

        private BigInteger _maxRawPT;
        public BigInteger MaxRawPlaintext
        {
            get
            {
                if (_maxRawPT == BigInteger.Zero)
                    _maxRawPT = BigInteger.Pow(2, getMaxPlaintextBits()) - BigInteger.One;
                return _maxRawPT;
            }
        }

        private BigInteger _maxRawPT_half;
        public BigInteger MaxEncryptableValue
        {
            get
            {
                if (_maxRawPT_half == BigInteger.Zero)
                    _maxRawPT_half = MaxRawPlaintext / 2;
                return _maxRawPT_half;
            }
        }

        public int getMaxPlaintextBits()
        {
            return 128; // 128 bit
        }

        public int getCiphertextBlocksize()
        {
            // We add 2 because last bit of a BigInteger is reserved to store its sign.
            // Therefore, theoretically, each part of ciphertext might need an extra byte to hold that one bit
            return ((P.BitCount() + 7) / 8) * 2 + 2;
        }
    }
}
