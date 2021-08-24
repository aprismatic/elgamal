using System;
using System.Numerics;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
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

        // TODO: Consider moving Encode and Decode to a separate class library. This way, MultiplyBy and DivideBy can be moved down to Homomorphism library
        public BigInteger Encode(BigInteger message) // TODO: Add tests now that this method is public
        {
            if (BigInteger.Abs(message) > keyStruct.MaxEncryptableValue)
                throw new ArgumentException($"Message to encrypt is too large. Message should be |m| < 2^{keyStruct.MaxPlaintextBits - 1}");

            if (message.Sign < 0)
                return keyStruct.MaxRawPlaintext + message + BigInteger.One;
            return message;
        }

        public BigInteger Decode(BigInteger encodedMessage) // TODO: Add tests now that this method is public
        {
            encodedMessage %= keyStruct.MaxRawPlaintext + BigInteger.One;
            if (encodedMessage > keyStruct.MaxEncryptableValue)
                return encodedMessage - keyStruct.MaxRawPlaintext - BigInteger.One;
            return encodedMessage;
        }

        public byte[] EncryptData(BigFraction message)
        {
            var ctbs = keyStruct.CiphertextBlocksize;
            var array = new byte[ctbs * 2];
            var arsp = array.AsSpan();

            encryptor.ProcessBigInteger(Encode(message.Numerator), arsp[..ctbs]);
            encryptor.ProcessBigInteger(Encode(message.Denominator), arsp[ctbs..]);

            return array;
        }

        public BigFraction DecryptData(byte[] data)
        {
            var halfblock = data.Length >> 1;
            var quarterblock = halfblock >> 1;
            var dsp = data.AsSpan();

            var numerator = decryptor.ProcessByteBlock(dsp[..quarterblock], dsp[quarterblock..halfblock]);
            var denominator = decryptor.ProcessByteBlock(dsp[halfblock..(halfblock + quarterblock)], dsp[(halfblock + quarterblock)..]);

            var res = new BigFraction(Decode(numerator), Decode(denominator));

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

        // TODO: Examine ways of moving this to the Homomorphism class library
        public byte[] MultiplyByPlaintext(byte[] first, BigFraction second) // TODO: Add overloads for BigInteger, Int32, Int64; same for DivideByPlaintext
        {
            var res = new byte[first.Length];
            var ressp = res.AsSpan();

            var halfblock = first.Length >> 1;
            var quarterblock = halfblock >> 1;

            var fsp = first.AsSpan();
            fsp[..quarterblock].CopyTo(ressp[..quarterblock]);
            fsp[halfblock..(halfblock + quarterblock)].CopyTo(ressp[halfblock..(halfblock + quarterblock)]);

            var nbb_bi = new BigInteger(fsp[quarterblock..halfblock]);
            var dbb_bi = new BigInteger(fsp[(halfblock + quarterblock)..]);

            nbb_bi = (nbb_bi * Encode(second.Numerator)) % keyStruct.P;
            dbb_bi = (dbb_bi * Encode(second.Denominator)) % keyStruct.P;

            nbb_bi.TryWriteBytes(ressp[quarterblock..halfblock], out _);
            dbb_bi.TryWriteBytes(ressp[(halfblock + quarterblock)..], out _);

            return res;
        }

        public byte[] DivideByPlaintext(byte[] first, BigFraction second)
        {
            return MultiplyByPlaintext(first, new BigFraction(second.Denominator, second.Numerator));
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
