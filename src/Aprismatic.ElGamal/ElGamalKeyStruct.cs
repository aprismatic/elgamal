using System.Numerics;

namespace Aprismatic.ElGamal
{
    public struct ElGamalKeyDefaults
    {
        public const int DefaultMaxPlaintextBits = 128;
    }

    public struct ElGamalKeyStruct
    {
        // PUBLIC KEY
        public readonly BigInteger P; // Moduluus of the cyclic group
        public readonly BigInteger G; // Generator of the group
        public readonly BigInteger Y;
        public readonly int MaxPlaintextBits;

        // PRIVATE KEY
        public readonly BigInteger X;
        
        // CONSTRUCTOR
        public ElGamalKeyStruct(BigInteger p, BigInteger g, BigInteger y, BigInteger x, int maxptbits)
        {
            P = p;
            PBitCount = p.BitCount();
            PLength = (PBitCount + 7) >> 3; // div 8

            G = g;
            Y = y;

            MaxPlaintextBits = maxptbits;
            MaxRawPlaintext = BigInteger.Pow(2, MaxPlaintextBits) - BigInteger.One;
            MaxEncryptableValue = MaxRawPlaintext >> 1;

            X = x;

            CiphertextBlocksize = PLength * 2 + 2;      // We add 2 because last bit of a BigInteger is reserved to store its sign.
            CiphertextLength = CiphertextBlocksize * 2; // Therefore, theoretically, each part of ciphertext might need an extra byte to hold that one bit
        }

        // HELPER VALUES
        // These values are derived from the pub/priv key and precomputed for faster processing
        public readonly BigInteger MaxRawPlaintext;
        public readonly BigInteger MaxEncryptableValue;

        public readonly int PBitCount;
        public readonly int PLength;

        public readonly int CiphertextBlocksize;
        public readonly int CiphertextLength;

        public ElGamalParameters ExportParameters(bool includePrivateParams)
        {
            // set the public values of the parameters
            var prms = new ElGamalParameters
            {
                P = P.ToByteArray(),
                G = G.ToByteArray(),
                Y = Y.ToByteArray(),
                MaxPlaintextBits = MaxPlaintextBits
            };

            // if required, include the private key values
            if (includePrivateParams)
                prms.X = X.ToByteArray();
            else
                prms.X = BigInteger.Zero.ToByteArray(); // ensure that we zero the value

            return prms;
        }
    }
}
