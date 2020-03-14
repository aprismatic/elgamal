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
        private ElGamalKeyStruct keyStruct;

        public ElGamalKeyStruct KeyStruct
        {
            get
            {
                if (NeedToGenerateKey())
                {
                    CreateKeyPair(KeySizeValue);
                }
                return keyStruct;
            }
            set => keyStruct = value;
        }

        public ElGamal()
        {
            // create the key struct and set all of the big integers to zero
            keyStruct = new ElGamalKeyStruct
            {
                P = BigInteger.Zero,
                G = BigInteger.Zero,
                Y = BigInteger.Zero,
                X = BigInteger.Zero
            };

            // set the default key size value
            KeySizeValue = 384;

            // set the range of legal keys
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };
        }

        private bool NeedToGenerateKey()
        {
            return (keyStruct.P == 0) && (keyStruct.G == 0) && (keyStruct.Y == 0);
        }

        private void CreateKeyPair(int keyStrength)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                // create the large prime number P, and regenerate P when P length is not same as KeySize
                do
                {
                    keyStruct.P = keyStruct.P.GenPseudoPrime(keyStrength, 16, rng);
                } while (keyStruct.getPLength() != keyStrength / 8);

                // create the two random numbers, which are smaller than P
                keyStruct.X = new BigInteger();
                keyStruct.X = keyStruct.X.GenRandomBits(keyStrength - 1, rng);
                keyStruct.G = new BigInteger();
                keyStruct.G = keyStruct.G.GenRandomBits(keyStrength - 1, rng);

                // compute Y
                keyStruct.Y = BigInteger.ModPow(keyStruct.G, keyStruct.X, keyStruct.P);
            }
        }

        public byte[] EncryptData(BigFraction message)
        {
            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }

            using (var encryptor = new ElGamalEncryptor(keyStruct))
            {
                var numerator = encryptor.ProcessBigInteger(message.Numerator);
                var denominator = encryptor.ProcessBigInteger(message.Denominator);
                var array = new byte[numerator.Length * 2];
                Array.Copy(numerator, 0, array, 0, numerator.Length);
                Array.Copy(denominator, 0, array, array.Length / 2, denominator.Length);
                return array;
            }
        }

        public BigFraction DecryptData(byte[] data)
        {
            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }

            var decryptor = new ElGamalDecryptor(keyStruct);

            var temp = new byte[data.Length / 2];
            Array.Copy(data, temp, data.Length / 2);
            var numerator = decryptor.ProcessByteBlock(temp);
            Array.Copy(data, data.Length / 2, temp, 0, data.Length / 2);
            var denominator = decryptor.ProcessByteBlock(temp);

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

        public void ImportParameters(ElGamalParameters parameters)
        {
            // obtain the  big integer values from the byte parameter values
            keyStruct.P = new BigInteger(parameters.P);
            keyStruct.G = new BigInteger(parameters.G);
            keyStruct.Y = new BigInteger(parameters.Y);

            if (parameters.X != null && parameters.X.Length > 0)
            {
                keyStruct.X = new BigInteger(parameters.X);
            }

            // set the length of the key based on the import
            KeySizeValue = keyStruct.P.BitCount();
        }

        public ElGamalParameters ExportParameters(bool includePrivateParams)
        {
            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }

            // create the parameter set and set the public values of the parameters
            var prms = new ElGamalParameters
            {
                P = keyStruct.P.ToByteArray(),
                G = keyStruct.G.ToByteArray(),
                Y = keyStruct.Y.ToByteArray()
            };

            // if required, include the private value, X
            if (includePrivateParams)
            {
                prms.X = keyStruct.X.ToByteArray();
            }
            else
            {
                // ensure that we zero the value
                prms.X = new byte[1];
            }

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

        public override void FromXmlString(string str)
        {
            var prms = new ElGamalParameters();

            var keyValues = XDocument.Parse(str).Element("ElGamalKeyValue");

            prms.P = Convert.FromBase64String((String)keyValues.Element("P") ?? "");
            prms.G = Convert.FromBase64String((String)keyValues.Element("G") ?? "");
            prms.Y = Convert.FromBase64String((String)keyValues.Element("Y") ?? "");
            prms.X = Convert.FromBase64String((String)keyValues.Element("X") ?? "");

            ImportParameters(prms);
        }
    }
}
