using ElGamalExt;
using ElGamalExt.BigInt;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace ElGamalTests
{
    [TestClass]
    public class ElGamalEncryptionTests
    {
        [TestMethod]
        public void TestZero()
        {
            ElGamalPaddingMode[] paddingModes = { ElGamalPaddingMode.LeadingZeros, ElGamalPaddingMode.TrailingZeros };

            foreach (var paddingMode in paddingModes)
            {
                for (var keySize = 384; keySize <= 1088; keySize += 8)
                {
                    ElGamal algorithm = new ElGamalManaged
                    {
                        Padding = paddingMode,
                        KeySize = keySize
                    };

                    ElGamal encryptAlgorithm = new ElGamalManaged();
                    encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                    ElGamal decryptAlgorithm = new ElGamalManaged();
                    decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                    var z = new BigInteger(0);
                    var z_bytes = z.ToByteArray();

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
            var rng = new RNGCryptoServiceProvider();

            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                ElGamal algorithm = new ElGamalManaged
                {
                    Padding = ElGamalPaddingMode.BigIntegerPadding,
                    KeySize = keySize
                };

                ElGamal encryptAlgorithm = new ElGamalManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                ElGamal decryptAlgorithm = new ElGamalManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var z = new BigInteger(); // Plaintext that is bigger than one block needs different padding,
                                          // and the encryption loses homomorphic properties
                z = z.GenRandomBits(rnd.Next(1, ((ElGamalManaged) algorithm).KeyStruct.getPlaintextBlocksize()), rng);

                var z_enc_bytes = encryptAlgorithm.EncryptData(z.ToByteArray());
                var z_dec_bytes = decryptAlgorithm.DecryptData(z_enc_bytes);

                var z_dec = new BigInteger(z_dec_bytes);

                Assert.AreEqual(z, z_dec, $"{Environment.NewLine}{Environment.NewLine}" +
                                          $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                          $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                          $"Algorithm parameters (FALSE):{Environment.NewLine}" +
                                          $"{algorithm.ToXmlString(false)}{Environment.NewLine}{Environment.NewLine}" +
                                          $"z: {z}{Environment.NewLine}{Environment.NewLine}" +
                                          $"z_dec: {z_dec}");
            }
        }

        [TestMethod]
        public void TestSpecificCases()
        {
            {
                var algorithmParamsTRUE = "<ElGamalKeyValue><P>hVWJyw9KZna4jNwese2+r6D4li7yXRG6/YIwsmPYY66NGpAigpYJR02IamdmHFe4+UznfJ3G4JZ3dpiI+o6PcHHEMPr88UlxoF9ZDAZ1XWmP7e7MpPPD/U1SK0hBy1bDy0O3Vx7ZAxD842hE</P><G>zjhHbkeMnG5SeApYj2+FDKWMx/+TN4rNrqk51e11C+uWo86oLCvTKqTOWDYAnbN15PrFuAr/bF35Alh3U2qytZCQmagh3E9VaqaRysS5aUvXfnBxlL0x+FvNtAK92r+eNMGE1UPZxVpk1DEu</G><Y>Vu0lxxhOIqluDQary3wx7A8J/cZ5B2xrtXQm8IiZz7b85yjcBr4I5T46JcbCJrLdheRzqdFH+/yE1Hegc/AJRU8mpAeikGTeuZ9wbLN0/QKfu67s6WtjVcjJNPCj+2LkKsN0T4f41+yEtho5</Y><Padding>LeadingZeros</Padding><X>1herKmqCq0sL+4DztH/DNbT27rylaa8L3a0Lb+z1r1aRih6Z+Rq3TtR6N0Q+kKDR8rzifq2G5xBs1MTYLOzcobmQYyXPJDHct/thTKsgaWD7J8P9Yrjj4hKP6iO6RHs1g4t2vuewLcPikFsn</X></ElGamalKeyValue>";
                var algorithmParamsFALSE = "<ElGamalKeyValue><P>hVWJyw9KZna4jNwese2+r6D4li7yXRG6/YIwsmPYY66NGpAigpYJR02IamdmHFe4+UznfJ3G4JZ3dpiI+o6PcHHEMPr88UlxoF9ZDAZ1XWmP7e7MpPPD/U1SK0hBy1bDy0O3Vx7ZAxD842hE</P><G>zjhHbkeMnG5SeApYj2+FDKWMx/+TN4rNrqk51e11C+uWo86oLCvTKqTOWDYAnbN15PrFuAr/bF35Alh3U2qytZCQmagh3E9VaqaRysS5aUvXfnBxlL0x+FvNtAK92r+eNMGE1UPZxVpk1DEu</G><Y>Vu0lxxhOIqluDQary3wx7A8J/cZ5B2xrtXQm8IiZz7b85yjcBr4I5T46JcbCJrLdheRzqdFH+/yE1Hegc/AJRU8mpAeikGTeuZ9wbLN0/QKfu67s6WtjVcjJNPCj+2LkKsN0T4f41+yEtho5</Y><Padding>LeadingZeros</Padding></ElGamalKeyValue>";

                ElGamal encryptAlgorithm = new ElGamalManaged();
                encryptAlgorithm.FromXmlString(algorithmParamsFALSE);

                ElGamal decryptAlgorithm = new ElGamalManaged();
                decryptAlgorithm.FromXmlString(algorithmParamsTRUE);

                var z = new BigInteger();
                BigInteger.TryParse("478878612704556930", out z);

                var z_enc_bytes = encryptAlgorithm.EncryptData(z.ToByteArray());
                var z_dec_bytes = decryptAlgorithm.DecryptData(z_enc_bytes);

                var z_dec = new BigInteger(z_dec_bytes);

                Assert.AreEqual(z, z_dec);
            }

            {
                ElGamal algorithm = new ElGamalManaged
                {
                    KeySize = 384,
                    Padding = ElGamalPaddingMode.TrailingZeros
                };

                ElGamal encryptAlgorithm = new ElGamalManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                ElGamal decryptAlgorithm = new ElGamalManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var z = new BigInteger();
                BigInteger.TryParse("427514703128554143101621639680", out z);

                var z_enc_bytes = encryptAlgorithm.EncryptData(z.ToByteArray());
                var z_dec_bytes = decryptAlgorithm.DecryptData(z_enc_bytes);

                var z_dec = new BigInteger(z_dec_bytes);

                Assert.AreEqual(z, z_dec);
            }

            {
                var algorithmParamsTRUE = "<ElGamalKeyValue><P>xWq9Kme204HeAuTBZenPYad7JYuqoSeKHveDlluGxOA3huROBtgA1LKT7GvHaohB</P><G>+kaqpuuPc4ziGbOftkw7HkSgOiovsPHvtPVLnVTsDmxLHDWA+0l08HFNz0RPQaAm</G><Y>D3oD1ePykN0L+h389YzXQRvYgKfQwgbPT6lP3sze75A7sOTfw4Y8qMQeGmM/yIcz</Y><Padding>TrailingZeros</Padding><X>c/v9OR4JwIUblP/xluK+6RErZTyLuJRwIb9gTjuW/1zzJkcjUu2HOchXbSW9zLw+</X></ElGamalKeyValue>";
                var algorithmParamsFALSE = "<ElGamalKeyValue><P>xWq9Kme204HeAuTBZenPYad7JYuqoSeKHveDlluGxOA3huROBtgA1LKT7GvHaohB</P><G>+kaqpuuPc4ziGbOftkw7HkSgOiovsPHvtPVLnVTsDmxLHDWA+0l08HFNz0RPQaAm</G><Y>D3oD1ePykN0L+h389YzXQRvYgKfQwgbPT6lP3sze75A7sOTfw4Y8qMQeGmM/yIcz</Y><Padding>TrailingZeros</Padding></ElGamalKeyValue>";

                ElGamal encryptAlgorithm = new ElGamalManaged();
                encryptAlgorithm.FromXmlString(algorithmParamsFALSE);

                ElGamal decryptAlgorithm = new ElGamalManaged();
                decryptAlgorithm.FromXmlString(algorithmParamsTRUE);

                var a = new BigInteger(248284864);
                var b = new BigInteger(674886484);

                var a_bytes = encryptAlgorithm.EncryptData(a.ToByteArray());
                var b_bytes = encryptAlgorithm.EncryptData(b.ToByteArray());

                var c_bytes = encryptAlgorithm.Multiply(a_bytes, b_bytes);

                var dec_c = new BigInteger(decryptAlgorithm.DecryptData(c_bytes));

                var ab_result = a * b;

                Assert.AreEqual(ab_result, dec_c);
            }
        }

        //[TestMethod] TODO: Fix text encryption and re-enable the test (implement ANSIX923 or PKCS97 padding)
        public void TestTextEncryption()
        {
            int keySize;
            var padding = ElGamalPaddingMode.TrailingZeros;
            var message = "Programming .NET Security";
            var plaintext = Encoding.Default.GetBytes(message);

            ElGamal algorithm = new ElGamalManaged()
            {
                Padding = padding
            };

            for (keySize = 384; keySize <= 1088; keySize += 8)
            {
                algorithm.KeySize = keySize;

                ElGamal encryptAlgorithm = new ElGamalManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                var ciphertext = encryptAlgorithm.EncryptData(plaintext);

                ElGamal decryptAlgorithm = new ElGamalManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var candidatePlaintext = decryptAlgorithm.DecryptData(ciphertext);

                CollectionAssert.AreEqual(plaintext, candidatePlaintext, $"Failed at keysize: {keySize}");
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
                    ElGamal algorithm = new ElGamalManaged
                    {
                        KeySize = keySize,
                        Padding = ElGamalPaddingMode.BigIntegerPadding
                    };

                    ElGamal encryptAlgorithm = new ElGamalManaged();
                    encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                    ElGamal decryptAlgorithm = new ElGamalManaged();
                    decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                    var a = new BigInteger(rnd.Next());
                    var b = new BigInteger(rnd.Next());

                    var a_bytes = encryptAlgorithm.EncryptData(a.ToByteArray());
                    var b_bytes = encryptAlgorithm.EncryptData(b.ToByteArray());

                    var c_bytes = encryptAlgorithm.Multiply(a_bytes, b_bytes);

                    var dec_c = new BigInteger(decryptAlgorithm.DecryptData(c_bytes));

                    var ab_result = a * b;

                    Assert.AreEqual(dec_c, ab_result, $"{Environment.NewLine}{Environment.NewLine}" +
                                                      $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                                      $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                                      $"Algorithm parameters (FALSE):{Environment.NewLine}" +
                                                      $"{algorithm.ToXmlString(false)}{Environment.NewLine}{Environment.NewLine}" +
                                                      $"a     : {a}{Environment.NewLine}{Environment.NewLine}" +
                                                      $"b     : {b}{Environment.NewLine}{Environment.NewLine}" +
                                                      $"a*b   : {ab_result}{Environment.NewLine}{Environment.NewLine}" +
                                                      $"dec_c : {dec_c}");
                }
            }
        }
    }
}
