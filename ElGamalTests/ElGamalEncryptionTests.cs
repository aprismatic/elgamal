using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ElGamalExt;
using System.Text;
using ElGamalExt.BigInt;
using System.Numerics;
using System.Security.Cryptography;

namespace ElGamalTests
{
    [TestClass]
    public class ElGamalEncryptionTests
    {

        [TestMethod]
        public void TestZero()
        {
            ElGamalPaddingMode[] paddingModes = { ElGamalPaddingMode.LeadingZeros, ElGamalPaddingMode.Zeros };

            foreach (var paddingMode in paddingModes)
            {
                for (var keySize = 384; keySize <= 1088; keySize += 8)
                {
                    ElGamal algorithm = new ElGamalManaged();
                    algorithm.Padding = paddingMode;
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
        public void TestRandomBigInteger()
        {
            var rnd = new Random();

            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                ElGamal algorithm = new ElGamalManaged();
                algorithm.Padding = ElGamalPaddingMode.LeadingZeros;
                algorithm.KeySize = keySize;

                ElGamal encryptAlgorithm = new ElGamalManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                ElGamal decryptAlgorithm = new ElGamalManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var z = new BigInteger();
                // Plaintext that is bigger than one block needs different padding and the encryption loses homomorphic properties
                z = z.genRandomBits(rnd.Next(1, (algorithm as ElGamalManaged).KeyStruct.getPlaintextBlocksize()), new RNGCryptoServiceProvider());

                var z_enc_bytes = encryptAlgorithm.EncryptData(z.getBytes());
                var z_dec_bytes = decryptAlgorithm.DecryptData(z_enc_bytes);

                var z_dec = new BigInteger(z_dec_bytes);

                Assert.AreEqual(z, z_dec);
            }
        }

        //[TestMethod] TODO: Fix text encryption and re-enable the test (implement ANSIX923 or PKCS97 padding)
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
            var iterations = 3;
            var rnd = new Random();

            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                for (var i = 0; i < iterations; i++)
                {
                    ElGamal algorithm = new ElGamalManaged();
                    algorithm.KeySize = keySize;
                    algorithm.Padding = ElGamalPaddingMode.LeadingZeros;

                    ElGamal encryptAlgorithm = new ElGamalManaged();
                    encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                    ElGamal decryptAlgorithm = new ElGamalManaged();
                    decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                    var a = new BigInteger(0);
                    var b = new BigInteger(0);

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
