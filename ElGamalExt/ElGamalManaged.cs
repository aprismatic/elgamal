/************************************************************************************
 This implementation of the ElGamal encryption scheme is based on the code from [1].

 This library is provided as-is and is covered by the MIT License [2] (except for the
 parts that belong to O'Reilly - they are covered by [3]).

 [1] Adam Freeman & Allen Jones, Programming .NET Security: O'Reilly Media, 2003,
     ISBN 9780596552275 (http://books.google.com.sg/books?id=ykXCNVOIEuQC)

 [2] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)

 [3] Tim O'Reilly, O'Reilly Policy on Re-Use of Code Examples from Books: website,
     2001, (http://www.oreillynet.com/pub/a/oreilly/ask_tim/2001/codepolicy.html)
 ************************************************************************************/

using System;
using System.Security.Cryptography;
using System.Numerics;
using ElGamalExt.BigInt;

namespace ElGamalExt
{
    public class ElGamalManaged : ElGamal
    {
        private ElGamalKeyStruct o_key_struct;

        public ElGamalManaged()
        {
            // create the key struct and set all of the big integers to zero
            o_key_struct = new ElGamalKeyStruct
            {
                P = BigInteger.Zero,
                G = BigInteger.Zero,
                Y = BigInteger.Zero,
                X = BigInteger.Zero
            };

            // set the default key size value
            KeySizeValue = 384;

            // set the default padding mode
            Padding = ElGamalPaddingMode.BigIntegerPadding;

            // set the range of legal keys
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };
        }

        public override string SignatureAlgorithm => "ElGamal";

        public override string KeyExchangeAlgorithm => "ElGamal";

        private void CreateKeyPair(int p_key_strength)
        {
            using (var x_random_generator = new RNGCryptoServiceProvider())
            {
                // create the large prime number, P
                o_key_struct.P = o_key_struct.P.GenPseudoPrime(p_key_strength, 16, x_random_generator);

                // create the two random numbers, which are smaller than P
                o_key_struct.X = new BigInteger();
                o_key_struct.X = o_key_struct.X.GenRandomBits(p_key_strength - 1, x_random_generator);
                o_key_struct.G = new BigInteger();
                o_key_struct.G = o_key_struct.G.GenRandomBits(p_key_strength - 1, x_random_generator);

                // compute Y
                o_key_struct.Y = BigInteger.ModPow(o_key_struct.G, o_key_struct.X, o_key_struct.P);

                o_key_struct.Padding = Padding;
            }
        }

        private bool NeedToGenerateKey()
        {
            return (o_key_struct.P == 0) && (o_key_struct.G == 0) && (o_key_struct.Y == 0);
        }

        public ElGamalKeyStruct KeyStruct
        {
            get
            {
                if (NeedToGenerateKey())
                {
                    CreateKeyPair(KeySizeValue);
                }
                return o_key_struct;
            }
            set
            {
                o_key_struct = value;
            }
        }

        public override void ImportParameters(ElGamalParameters p_parameters)
        {
            // obtain the  big integer values from the byte parameter values
            o_key_struct.P = new BigInteger(p_parameters.P);
            o_key_struct.G = new BigInteger(p_parameters.G);
            o_key_struct.Y = new BigInteger(p_parameters.Y);
            o_key_struct.Padding = p_parameters.Padding;

            if (p_parameters.X != null && p_parameters.X.Length > 0)
            {
                o_key_struct.X = new BigInteger(p_parameters.X);
            }

            // set the length of the key based on the import
            KeySizeValue = o_key_struct.P.BitCount();
            Padding = o_key_struct.Padding;
        }

        public override ElGamalParameters ExportParameters(bool p_include_private_params)
        {
            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }

            // create the parameter set and set the public values of the parameters
            var x_params = new ElGamalParameters
            {
                P = o_key_struct.P.ToByteArray(),
                G = o_key_struct.G.ToByteArray(),
                Y = o_key_struct.Y.ToByteArray(),
                Padding = o_key_struct.Padding
            };

            // if required, include the private value, X
            if (p_include_private_params)
            {
                x_params.X = o_key_struct.X.ToByteArray();
            }
            else
            {
                // ensure that we zero the value
                x_params.X = new byte[1];
            }

            return x_params;
        }

        public override byte[] EncryptData(byte[] p_data)
        {
            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }

            using (var x_enc = new ElGamalEncryptor(o_key_struct))
            {
                return x_enc.ProcessData(p_data);
            }
        }

        public override byte[] DecryptData(byte[] p_data)
        {
            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }

            var x_enc = new ElGamalDecryptor(o_key_struct);

            return x_enc.ProcessData(p_data);
        }

        protected override void Dispose(bool p_bool)
        {
            // do nothing - no unmanaged resources to release
        }

        public override byte[] Sign(byte[] p_hashcode)
        {
            throw new System.NotImplementedException();
        }

        public override bool VerifySignature(byte[] p_hashcode, byte[] p_signature)
        {
            throw new System.NotImplementedException();
        }

        public override byte[] Multiply(byte[] p_first, byte[] p_second)
        {
            var blocksize = o_key_struct.getCiphertextBlocksize();

            if (p_first.Length != blocksize)
            {
                throw new ArgumentException("Ciphertext to multiply should be exactly one block long.", nameof(p_first));
            }
            if (p_second.Length != blocksize)
            {
                throw new ArgumentException("Ciphertext to multiply should be exactly one block long.", nameof(p_second));
            }

            return Homomorphism.ElGamalHomomorphism.Multiply(p_first, p_second, o_key_struct.P.ToByteArray());
        }
    }
}
