using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Aprismatic.ElGamalExt.Homomorphism;

namespace Aprismatic.ElGamalExt
{
    public class ElGamal : AsymmetricAlgorithm
    {
        private readonly ElGamalKeyStruct keyStruct;
        private readonly ElGamalEncryptor encryptor;
        private readonly ElGamalDecryptor decryptor;

        public int MaxPlaintextBits => keyStruct.MaxPlaintextBits;
        public BigInteger P => keyStruct.P;
        public int PLength => keyStruct.PLength;
        public int CiphertextLength => keyStruct.CiphertextLength;

        // TODO: Constructors should allow to specify MaxPlaintextBits
        public ElGamal(int keySize, int precomputedQueueSize = 10) // TODO: Constructor should probably optionally accept an RNG
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };
            KeySizeValue = keySize; // TODO: Validate that key is of legal size
            keyStruct = CreateKeyPair(ElGamalKeyDefaults.DefaultMaxPlaintextBits);
            encryptor = new ElGamalEncryptor(keyStruct, precomputedQueueSize);
            decryptor = new ElGamalDecryptor(keyStruct);
        }

        public ElGamal(ElGamalParameters prms, int precomputedQueueSize = 10) // TODO: Consolidate constructors in one method
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };

            keyStruct = new ElGamalKeyStruct(
                new BigInteger(prms.P),
                new BigInteger(prms.G),
                new BigInteger(prms.Y),
                new BigInteger(prms.X),
                prms.MaxPlaintextBits
            );

            KeySizeValue = keyStruct.PLength * 8; // TODO: Validate that key is of legal size

            encryptor = new ElGamalEncryptor(keyStruct, precomputedQueueSize);
            decryptor = new ElGamalDecryptor(keyStruct);
        }

        public ElGamal(string Xml, int precomputedQueueSize = 10) : this(ElGamalParameters.FromXml(Xml), precomputedQueueSize)
        { }

        private ElGamalKeyStruct CreateKeyPair(int maxptbits) // TODO: This method should probably move to KeyStruct
        {
            BigInteger P, G, Y, X;

            using var rng = RandomNumberGenerator.Create();

            // create the large prime number P, and regenerate P when P length is not same as KeySize in bytes
            do
            {
                P = BigInteger.Zero.GenPseudoPrime(KeySizeValue, 16, rng);
            } while (P.BitCount() < KeySizeValue - 7);

            // create the two random numbers, which are smaller than P
            X = BigInteger.Zero.GenRandomBits(KeySizeValue - 1, rng);
            G = BigInteger.Zero.GenRandomBits(KeySizeValue - 1, rng);

            Y = BigInteger.ModPow(G, X, P);

            return new ElGamalKeyStruct(P, G, Y, X, maxptbits);
        }

        public byte[] EncryptData(BigFraction message)
        {
            var ctbs = keyStruct.CiphertextBlocksize;
            var array = new byte[ctbs * 2];

            encryptor.ProcessBigInteger(message.Numerator, array.AsSpan(0, ctbs));
            encryptor.ProcessBigInteger(message.Denominator, array.AsSpan(ctbs, ctbs));

            return array;
        }

        public BigFraction DecryptData(byte[] data)
        {
            var halfblock = data.Length >> 1;
            var quarterblock = halfblock >> 1;
            var dsp = data.AsSpan();

            var numerator = decryptor.ProcessByteBlock(dsp.Slice(0, quarterblock), dsp.Slice(quarterblock, quarterblock));
            var denominator = decryptor.ProcessByteBlock(dsp.Slice(halfblock, quarterblock), dsp.Slice(halfblock + quarterblock, quarterblock));

            var res = new BigFraction(numerator, denominator);

            return res;
        }

        public byte[] Multiply(byte[] first, byte[] second)
        {
            return ElGamalHomomorphism.Multiply(first, second, keyStruct.P.ToByteArray());
        }

        public byte[] Divide(byte[] first, byte[] second)
        {
            return ElGamalHomomorphism.Divide(first, second, keyStruct.P.ToByteArray());
        }

        public ElGamalParameters ExportParameters(bool includePrivateParams) => keyStruct.ExportParameters(includePrivateParams);

        public override string ToXmlString(bool includePrivateParameters)
        {
            var prms = ExportParameters(includePrivateParameters);
            return prms.ToXml(includePrivateParameters);
        }

        public new void Dispose() => encryptor.Dispose();
    }
}
