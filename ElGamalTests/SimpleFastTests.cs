using Aprismatic.BigFraction;
using ElGamalExt;
using System;
using System.Numerics;
using System.Security.Cryptography;
using Xunit;
using Xunit.Abstractions;

namespace ElGamalTests
{
    public class SimpleFastTests : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new Random();
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();

        public SimpleFastTests(ITestOutputHelper output)
        {
            this.output = output;
        }

        public void Dispose()
        {
            rng.Dispose();
        }

        [Fact(DisplayName = "Specific cases")]
        public void TestSpecificCases()
        {
            {
                var algorithm = new ElGamal
                {
                    KeySize = 384
                };

                var a = new BigInteger(2048);
                var a_bytes = algorithm.EncryptData(a);
                var dec_a = algorithm.DecryptData(a_bytes);
                Assert.Equal(a, dec_a);

                algorithm.Dispose();
            }

            {
                var algorithm = new ElGamal
                {
                    KeySize = 384
                };

                var a = new BigInteger(138);
                var a_bytes = algorithm.EncryptData(a);
                var dec_a = algorithm.DecryptData(a_bytes);

                Assert.Equal(a, dec_a);

                algorithm.Dispose();
            }

            { // based on https://github.com/bazzilic/PaillierExt/issues/15
                for (var keySize = 384; keySize <= 1088; keySize += 8)
                {
                    var algorithm = new ElGamal
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

                    algorithm.Dispose();
                }
            }
        }

        [Fact(DisplayName = "Simple negatives")]
        public void TestNegativeCases()
        {
            { // Simple negative cases
                var algorithm = new ElGamal
                {
                    KeySize = 384
                };

                //Negative Number En/Decryption
                var a = new BigFraction(new Decimal(-94660895));
                var a_enc = algorithm.EncryptData(a);
                var a_dec = algorithm.DecryptData(a_enc);
                Assert.Equal(a, a_dec);

                var b = new BigFraction(new Decimal(45651255));
                var b_enc = algorithm.EncryptData(b);
                var b_dec = algorithm.DecryptData(b_enc);
                Assert.Equal(b, b_dec);


                //Negative Numbers Multiplication
                var mul_bytes = algorithm.Multiply(a_enc, b_enc);
                var mul_dec = algorithm.DecryptData(mul_bytes);
                Assert.Equal(a * b, mul_dec);

                //Negative Numbers Division
                var div_bytes = algorithm.Divide(a_enc, b_enc);
                var div_dec = algorithm.DecryptData(div_bytes);
                Assert.Equal(a / b, div_dec);

                algorithm.Dispose();
            }
        }

        [Fact(DisplayName = "Simple fractions")]
        public void TestFloatingCases()
        {
            {
                var algorithm = new ElGamal
                {
                    KeySize = 384
                };

                //Positive Floating Point Number En/Decryption
                var a = new BigFraction(new Decimal(12.5467));
                var a_enc = algorithm.EncryptData(a);
                var a_dec = algorithm.DecryptData(a_enc);
                Assert.Equal(a, a_dec);


                //Negative Floating Point Number En/Decryption
                var b = new BigFraction(new Decimal(-4554545.1231));
                var b_enc = algorithm.EncryptData(b);
                var b_dec = algorithm.DecryptData(b_enc);
                Assert.Equal(b, b_dec);


                //Floating Point Numbers Multiplication
                var mul_bytes = algorithm.Multiply(a_enc, b_enc);
                var mul_dec = algorithm.DecryptData(mul_bytes);
                Assert.Equal(a * b, mul_dec);

                //Floating Point Numbers Division
                var div_bytes = algorithm.Divide(a_enc, b_enc);
                var div_dec = algorithm.DecryptData(div_bytes);
                Assert.Equal(a / b, div_dec);

                algorithm.Dispose();
            }
        }
    }
}
