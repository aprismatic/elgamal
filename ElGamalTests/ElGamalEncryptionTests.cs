using BigIntegerExt;
using ElGamalExt;
using System;
using System.Numerics;
using Numerics;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace ElGamalTests
{
    public class ElGamalEncryptionTests
    {
		private static readonly double exp = 1e8;

		private readonly ITestOutputHelper output;

		public ElGamalEncryptionTests(ITestOutputHelper output)
		{
			this.output = output;
		}

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

		[Fact(DisplayName = "Floating cases")]
		public void TestFloatingCases()
		{
			{
				ElGamal algorithm = new ElGamal
				{
					KeySize = 384
				};

				double a_row = 2.5;
				double a_encode = a_row * exp;
				var a = new BigInteger(a_encode);
				var a_byte = algorithm.EncryptData(a);
				var a_dec = algorithm.DecryptData(a_byte);
				object a_obj = a_dec;
				BigInteger a_unbox = (BigInteger)a_obj;
				double a_decode = (double)a_unbox / exp;
				Assert.Equal(a_row, a_decode);

				double b_row = -20;
				double b_encode = b_row * exp;
				var b = new BigInteger(b_encode);
				var b_byte = algorithm.EncryptData(b);
				var b_dec = algorithm.DecryptData(b_byte);
				object b_obj = b_dec;
				BigInteger b_unbox = (BigInteger)b_obj;
				double b_decode = (double)b_unbox / exp;
				Assert.Equal(b_row, b_decode);

				double mul_row = a_row * b_row;
				var mul_byte = algorithm.Multiply(a_byte, b_byte);
				var mul_dec = algorithm.DecryptData(mul_byte);
				object mul_obj = mul_dec;
				BigInteger mul_unbox = (BigInteger)mul_obj;
				double mul_decode = (double)mul_unbox / (exp * exp);
				Assert.Equal(mul_row, mul_decode);
			}
		}
	}
}