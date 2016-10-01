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
            ElGamalPaddingMode[] paddingModes = { ElGamalPaddingMode.LeadingZeros, ElGamalPaddingMode.Zeros };

            foreach (var paddingMode in paddingModes)
            {
                algorithm.Padding = paddingMode;

                for (var keySize = 384; keySize <= 1088; keySize += 8)
                {
                    algorithm.KeySize = keySize;

                    ElGamal encryptAlgorithm = new ElGamalManaged();
                    encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                    ElGamal decryptAlgorithm = new ElGamalManaged();
                    decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                    var z = new BigInteger(0);
                    var z_bytes = z.getBytes();

                    var z_enc_bytes = encryptAlgorithm.EncryptData(z_bytes);
                    var z_dec_bytes = decryptAlgorithm.DecryptData(z_enc_bytes);

                    var z_dec = new BigInteger(z_dec_bytes);

                    Assert.AreEqual(z, z_dec);
                }
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

        //[TestMethod] TODO: Fix text encryption and re-enable the test
        public void TestTextEncryption()
        {
            int keySize;
            var padding = ElGamalPaddingMode.Zeros;
            var message = "Programming .NET Security";
            var plaintext = Encoding.Default.GetBytes(message);

            ElGamal algorithm = new ElGamalManaged();

            algorithm.Padding = padding;

            for (keySize = 384; keySize <= 1088; keySize += 8)
            {
                algorithm.KeySize = keySize;

                ElGamal encryptAlgorithm = new ElGamalManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                var ciphertext = encryptAlgorithm.EncryptData(plaintext);

                ElGamal decryptAlgorithm = new ElGamalManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var candidatePlaintext = decryptAlgorithm.DecryptData(ciphertext);

                CollectionAssert.AreEqual(plaintext, candidatePlaintext, "Failed at keysize: " + keySize.ToString());
            }
        }

        [TestMethod]
        public void TestMultiplication_Batch()
        {
            var rnd = new Random();
            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                for (var i = 0; i < 3; i++)
                // testing for 3 sets of keys
                {
                    ElGamal algorithm = new ElGamalManaged();
                    algorithm.KeySize = keySize;
                    algorithm.Padding = ElGamalPaddingMode.LeadingZeros;

                    ElGamal encryptAlgorithm = new ElGamalManaged();
                    encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                    ElGamal decryptAlgorithm = new ElGamalManaged();
                    decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                    var a = new BigInteger(rnd.Next(32768));
                    var b = new BigInteger(rnd.Next(32768));

                    var a_bytes = encryptAlgorithm.EncryptData(a.getBytes());
                    var b_bytes = encryptAlgorithm.EncryptData(b.getBytes());

                    var c_bytes = encryptAlgorithm.Multiply(a_bytes, b_bytes);

                    var dec_c = new BigInteger(decryptAlgorithm.DecryptData(c_bytes));

                    var ab_result = a * b;

                    Assert.AreEqual(dec_c, ab_result);
                }
            }
        }
    }
}
