using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ElGamalExt;
using System.Text;
using System.Security.Cryptography;

namespace ElGamalTests
{
    [TestClass]
    public class ElGamalEncryptionTests
    {
        [TestMethod]
        public void TestZero()
        {
            ElGamal algorithm = new ElGamalManaged();
            algorithm.Padding = ElGamalPaddingMode.Zeros;

            for (int keySize = 384; keySize <= 1088; keySize += 8)
            {
                algorithm.KeySize = keySize;

                ElGamal encryptAlgorithm = new ElGamalManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                ElGamal decryptAlgorithm = new ElGamalManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var z = new BigInteger(0);

                var z_enc = encryptAlgorithm.EncryptData(z.getBytes());
                var z_dec = decryptAlgorithm.DecryptData(z_enc);

                var zero_array = new byte[z_dec.Length];
                Array.Clear(zero_array, 0, zero_array.Length - 1);

                CollectionAssert.AreEqual(zero_array, z_dec);
            }
        }

        [TestMethod]
        public void TestZero_DifferentPaddingMode()
        {
            ElGamal algorithm = new ElGamalManaged();
            algorithm.KeySize = 384;

            ElGamalPaddingMode[] paddingModes = { ElGamalPaddingMode.LeadingZeros, ElGamalPaddingMode.Zeros };

            foreach (var paddingMode in paddingModes)
            {
                algorithm.Padding = paddingMode;

                ElGamal encryptAlgorithm = new ElGamalManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                ElGamal decryptAlgorithm = new ElGamalManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var z = new BigInteger(0);

                var z_enc = encryptAlgorithm.EncryptData(z.getBytes());
                var z_dec = decryptAlgorithm.DecryptData(z_enc);

                var zero_array = new byte[z_dec.Length];
                Array.Clear(zero_array, 0, zero_array.Length - 1);

                CollectionAssert.AreEqual(zero_array, z_dec, "Failed on padding mode: " + paddingMode.ToString());
            }
        }

        [TestMethod]
        public void TestRandomBI()
        {
            // Failed test because of zeroes

            ElGamal algorithm = new ElGamalManaged();
            algorithm.Padding = ElGamalPaddingMode.LeadingZeros;

            for (algorithm.KeySize = 384; algorithm.KeySize <= 1088; algorithm.KeySize += 8)
            {
                ElGamal encryptAlgorithm = new ElGamalManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                ElGamal decryptAlgorithm = new ElGamalManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var z = new BigInteger();
                z.genRandomBits(new Random().Next(1, 2241), new RNGCryptoServiceProvider());

                var z_enc = encryptAlgorithm.EncryptData(z.getBytes());
                var z_dec = decryptAlgorithm.DecryptData(z_enc);

                CollectionAssert.AreEqual(z.getBytes(), z_dec);
            }
        }

        [TestMethod]
        public void TestTextEncryption()
        {
            int keySize;
            ElGamalPaddingMode padding = ElGamalPaddingMode.Zeros;
            string message = "Programming .NET Security";
            var plaintext = Encoding.Default.GetBytes(message);

            ElGamal algorithm = new ElGamalManaged();

            algorithm.Padding = padding;

            for (keySize = 384; keySize <= 1088; keySize += 8)
            {
                algorithm.KeySize = keySize;

                string parametersXML = algorithm.ToXmlString(true);

                ElGamal encryptAlgorithm = new ElGamalManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                byte[] ciphertext = encryptAlgorithm.EncryptData(plaintext);

                ElGamal decryptAlgorithm = new ElGamalManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                byte[] candidatePlaintext = decryptAlgorithm.DecryptData(ciphertext);

                CollectionAssert.AreEqual(plaintext, candidatePlaintext, "Failed at keysize: " + keySize.ToString());
            }
        }

        [TestMethod]
        public void TestMultiplication_Batch()
        {
            var rnd = new Random();
            for (int keySize = 384; keySize <= 1088; keySize += 8)
            {
                for (int i = 0; i < 3; i++)
                // testing for 3 sets of keys
                {
                    ElGamal algorithm = new ElGamalManaged();
                    algorithm.KeySize = keySize;
                    algorithm.Padding = ElGamalPaddingMode.LeadingZeros;
                    string parametersXML = algorithm.ToXmlString(true);

                    ElGamal encryptAlgorithm = new ElGamalManaged();
                    encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                    ElGamal decryptAlgorithm = new ElGamalManaged();
                    decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                    int error_counter = 0;
                    for (int j = 0; j < 50; j++)
                    // testing for 50 pairs of random numbers
                    {
                        var a = new BigInteger(rnd.Next());
                        var b = new BigInteger(rnd.Next());

                        var a_bytes = encryptAlgorithm.EncryptData(a.getBytes());
                        var b_bytes = encryptAlgorithm.EncryptData(b.getBytes());

                        var c_bytes = encryptAlgorithm.Multiply(a_bytes, b_bytes);

                        var dec_c = new BigInteger(decryptAlgorithm.DecryptData(c_bytes));
                        var dec_a = new BigInteger(decryptAlgorithm.DecryptData(a_bytes));
                        var dec_b = new BigInteger(decryptAlgorithm.DecryptData(b_bytes));

                        var ab_result = a * b;
                        if (dec_c != ab_result)
                        {
                            error_counter++;
                        }
                        Assert.AreEqual(dec_c, ab_result);
                    }
                }
            }
        }
    }
}
