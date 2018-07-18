using BigIntegerExt;
using ElGamalExtModified;
using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace ElGamalTests
{
    public class ElGamalEncryptionTests
    {
       
        [Fact(DisplayName = "Random BigIntegers")]
        public void TestRandomBigInteger()
        {
            var rnd = new Random();
            var rng = new RNGCryptoServiceProvider();

            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                ElGamalModified algorithm = new ElGamalModifiedManaged
                {
                    //Padding = ElGamalPaddingMode.BigIntegerPadding,
                    KeySize = keySize
                };

                ElGamalModified encryptAlgorithm = new ElGamalModifiedManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                ElGamalModified decryptAlgorithm = new ElGamalModifiedManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var z = new BigInteger(); // Plaintext that is bigger than one block needs different padding,
                                          // and the encryption loses homomorphic properties
                z = z.GenRandomBits(rnd.Next(1, ((ElGamalModifiedManaged) algorithm).KeyStruct.getPlaintextBlocksize()), rng);

                var z_enc_bytes = encryptAlgorithm.EncryptData(z);
                var z_dec_bytes = decryptAlgorithm.DecryptData(z_enc_bytes);

                Assert.True(z == z_dec_bytes, $"{Environment.NewLine}{Environment.NewLine}" +
                                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                        $"Algorithm parameters (FALSE):{Environment.NewLine}" +
                                        $"{algorithm.ToXmlString(false)}{Environment.NewLine}{Environment.NewLine}" +
                                        $"z: {z}{Environment.NewLine}{Environment.NewLine}" +
                                        $"z_dec: {z_dec_bytes}");
            }
        }

        [Fact(DisplayName = "Specific cases")]
        public void TestSpecificCases()
        {
            {
                ElGamalModified algorithm = new ElGamalModifiedManaged
                {
                    KeySize = 384,
                    //Padding = ElGamalPaddingMode.BigIntegerPadding
                };

                var a = new BigInteger(2048);
                var a_bytes = algorithm.EncryptData(a);
                var dec_a = algorithm.DecryptData(a_bytes);

                Assert.Equal(a, dec_a);
            }

            {
                ElGamalModified algorithm = new ElGamalModifiedManaged
                {
                    KeySize = 384,
                    //Padding = ElGamalPaddingMode.BigIntegerPadding
                };

                var a = new BigInteger(138);
                var a_bytes = algorithm.EncryptData(a);
                var dec_a = algorithm.DecryptData(a_bytes);

                Assert.Equal(a, dec_a);
            }
        }


        [Fact(DisplayName = "Multiplication batch")]
        public void TestMultiplication_Batch()
        {
            var iterations = 3;
            var rnd = new Random();

            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                for (var i = 0; i < iterations; i++)
                {
                    ElGamalModified algorithm = new ElGamalModifiedManaged
                    {
                        KeySize = keySize,
                        //Padding = ElGamalPaddingMode.BigIntegerPadding
                    };

                    ElGamalModified encryptAlgorithm = new ElGamalModifiedManaged();
                    encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                    ElGamalModified decryptAlgorithm = new ElGamalModifiedManaged();
                    decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                    var a = new BigInteger(rnd.Next());
                    var b = new BigInteger(rnd.Next());

                    var a_bytes = encryptAlgorithm.EncryptData(a);
                    var b_bytes = encryptAlgorithm.EncryptData(b);

                    var c_bytes = encryptAlgorithm.Multiply(a_bytes, b_bytes);

                    var dec_c = decryptAlgorithm.DecryptData(c_bytes);

                    var ab_result = a * b;

                    Assert.True(dec_c == ab_result, $"{Environment.NewLine}{Environment.NewLine}" +
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

        [Fact(DisplayName = "From issue #15")]
        public void Test_FromIssue_15() // based on https://github.com/bazzilic/PaillierExt/issues/15
        {
            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                ElGamalModified algorithm = new ElGamalModifiedManaged
                {
                    KeySize = keySize,
                    //Padding = ElGamalPaddingMode.BigIntegerPadding
                };

                var prod = algorithm.EncryptData(new BigInteger(1));
                var three = algorithm.EncryptData(new BigInteger(3));

                for (var i = 0; i < 30; i++)
                {
                    prod = algorithm.Multiply(prod, three);
                }

                var sum_dec = algorithm.DecryptData(prod);

                Assert.Equal(new BigInteger(205891132094649), sum_dec);
            }
        }
    }
}
