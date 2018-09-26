using BigIntegerExt;
using ElGamalExt;
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
                ElGamal algorithm = new ElGamal
                {
                    KeySize = keySize
                };

                ElGamal encryptAlgorithm = new ElGamal();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                ElGamal decryptAlgorithm = new ElGamal();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var z = new BigInteger(); // Plaintext that is bigger than one block needs different padding,
                                          // and the encryption loses homomorphic properties
                z = z.GenRandomBits(rnd.Next(1, ((ElGamal) algorithm).KeyStruct.getPlaintextBlocksize()), rng);

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
                ElGamal algorithm = new ElGamal
				{
                    KeySize = 384
                };

                var a = new BigInteger(2048);
                var a_bytes = algorithm.EncryptData(a);
                var dec_a = algorithm.DecryptData(a_bytes);
                Assert.Equal(a, dec_a);
            }

            {
                ElGamal algorithm = new ElGamal
				{
                    KeySize = 384
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
                    ElGamal algorithm = new ElGamal
					{
                        KeySize = keySize
                    };

                    ElGamal encryptAlgorithm = new ElGamal();
                    encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                    ElGamal decryptAlgorithm = new ElGamal();
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
                ElGamal algorithm = new ElGamal
				{
                    KeySize = keySize
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

        [Fact(DisplayName = "Negative cases")]
        public void TestNegativeCases()
        {
            {
                ElGamal algorithm = new ElGamal
				{
                    KeySize = 384
                };

                var a = new BigInteger(-2048);
                var a_bytes = algorithm.EncryptData(a);
                var dec_a = algorithm.DecryptData(a_bytes);
                Assert.Equal(a, dec_a);

				var a_2 = new BigInteger(138);
				var a_bytes_2 = algorithm.EncryptData(a_2);
				var dec_a_2 = algorithm.DecryptData(a_bytes_2);

				Assert.Equal(a_2, dec_a_2);

				var bytes_mul = algorithm.Multiply(a_bytes, a_bytes_2);
				var dec_mul = algorithm.DecryptData(bytes_mul);

				Assert.Equal(a * a_2, dec_mul);
			}
        }
    }
}
