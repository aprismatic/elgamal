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

        public int MaxPlaintextBits => ElGamalKeyStruct.MaxPlaintextBits;
        public BigInteger P => keyStruct.P;
        public int PLength => keyStruct.PLength;
        public int CiphertextLength => keyStruct.CiphertextLength;

        public ElGamal(int keySize, int precomputedQueueSize = 10)
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };
            KeySizeValue = keySize;
            keyStruct = CreateKeyPair();
            encryptor = new ElGamalEncryptor(keyStruct, precomputedQueueSize);
            decryptor = new ElGamalDecryptor(keyStruct);
        }

        public ElGamal(ElGamalParameters parameters, int precomputedQueueSize = 10)
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };

            keyStruct = new ElGamalKeyStruct(
                new BigInteger(parameters.P),
                new BigInteger(parameters.G),
                new BigInteger(parameters.Y),
                (parameters.X?.Length ?? 0) > 0 ? new BigInteger(parameters.X) : BigInteger.Zero
            );

            KeySizeValue = keyStruct.PLength * 8;

            encryptor = new ElGamalEncryptor(keyStruct, precomputedQueueSize);
            decryptor = new ElGamalDecryptor(keyStruct);
        }

        public ElGamal(string Xml, int precomputedQueueSize = 10)
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };

            var prms = new ElGamalParameters();
            var keyValues = XDocument.Parse(Xml).Element("ElGamalKeyValue");
            prms.P = Convert.FromBase64String((String)keyValues.Element("P") ?? "");
            prms.G = Convert.FromBase64String((String)keyValues.Element("G") ?? "");
            prms.Y = Convert.FromBase64String((String)keyValues.Element("Y") ?? "");
            prms.X = Convert.FromBase64String((String)keyValues.Element("X") ?? "");

            keyStruct = new ElGamalKeyStruct(
                new BigInteger(prms.P),
                new BigInteger(prms.G),
                new BigInteger(prms.Y),
                new BigInteger(prms.X)
            );

            KeySizeValue = keyStruct.PLength * 8;

            encryptor = new ElGamalEncryptor(keyStruct, precomputedQueueSize);
            decryptor = new ElGamalDecryptor(keyStruct);
        }

        private ElGamalKeyStruct CreateKeyPair()
        {
            BigInteger P, G, Y, X;

            using (var rng = RandomNumberGenerator.Create())
            {
                // create the large prime number P, and regenerate P when P length is not same as KeySize in bytes
                do
                {
                    P = BigInteger.Zero.GenPseudoPrime(KeySizeValue, 16, rng);
                } while (P.BitCount() < KeySizeValue - 7);

                // create the two random numbers, which are smaller than P
                X = BigInteger.Zero.GenRandomBits(KeySizeValue - 1, rng);
                G = BigInteger.Zero.GenRandomBits(KeySizeValue - 1, rng);

                Y = BigInteger.ModPow(G, X, P);
            }

            return new ElGamalKeyStruct(P, G, Y, X);
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

        public ElGamalParameters ExportParameters(bool includePrivateParams)
        {
            // set the public values of the parameters
            var prms = new ElGamalParameters
            {
                P = keyStruct.P.ToByteArray(),
                G = keyStruct.G.ToByteArray(),
                Y = keyStruct.Y.ToByteArray(),
                X = includePrivateParams           // if required, include the private value, X
                    ? keyStruct.X.ToByteArray()
                    : new byte[1]
            };

            return prms;
        }

        public override string ToXmlString(bool includePrivateParameters)
        {
            var prms = ExportParameters(includePrivateParameters);

            var sb = new StringBuilder();

            sb.Append("<ElGamalKeyValue>");

            sb.Append("<P>" + Convert.ToBase64String(prms.P) + "</P>");
            sb.Append("<G>" + Convert.ToBase64String(prms.G) + "</G>");
            sb.Append("<Y>" + Convert.ToBase64String(prms.Y) + "</Y>");

            if (includePrivateParameters)
            {
                // we need to include X, which is the part of private key
                sb.Append("<X>" + Convert.ToBase64String(prms.X) + "</X>");
            }

            sb.Append("</ElGamalKeyValue>");

            return sb.ToString();
        }

        public new void Dispose()
        {
            encryptor.Dispose();
        }
    }
}
