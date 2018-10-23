using Aprismatic.BigFraction;
using BigIntegerExt;
using ElGamalExt;
using System;
using System.Numerics;
using System.Security.Cryptography;
using Xunit;
using Xunit.Abstractions;

namespace ElGamalTests
{
    public class IntMulDiv : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new Random();
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();

        public IntMulDiv(ITestOutputHelper output)
        {
            this.output = output;
        }

        public void Dispose()
        {
            rng.Dispose();
        }

        [Fact(DisplayName = "INT (MUL/DIV, +-)")]
        public void TestMultiplication_Batch()
        {
            var rnd = new Random();
            var rng = new RNGCryptoServiceProvider();

            for (var i = 0; i < Globals.iterations; i++)
            {
                for (var keySize = 384; keySize <= 1088; keySize += 8)
                {
                    var algorithm = new ElGamal
                    {
                        KeySize = keySize
                    };

                    var encryptAlgorithm = new ElGamal();
                    encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                    var decryptAlgorithm = new ElGamal();
                    decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                    BigInteger a, b;
                    do
                    {
                        a = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.KeyStruct.getMaxPlaintextBits() / 4), rng);
                    } while (a == 0);
                    do
                    {
                        b = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.KeyStruct.getMaxPlaintextBits() / 4), rng);
                    } while (b == 0);

                    if (rnd.Next() % 2 == 0) // randomly change signs
                        a = -a;
                    if (rnd.Next() % 2 == 0)
                        b = -b;

                    var a_enc = encryptAlgorithm.EncryptData(a);
                    var b_enc = encryptAlgorithm.EncryptData(b);


                    // Multiplication
                    var axb_enc = decryptAlgorithm.Multiply(a_enc, b_enc);
                    var axb_dec = decryptAlgorithm.DecryptData(axb_enc);
                    Assert.True(axb_dec == a * b, $"{Environment.NewLine}{Environment.NewLine}" +
                                                  $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                                  $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a * b   : {a * b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"axb_dec : {axb_dec}");

                    var bxa_enc = decryptAlgorithm.Multiply(b_enc, a_enc); // verify transitivity
                    var bxa_dec = decryptAlgorithm.DecryptData(bxa_enc);
                    Assert.True(bxa_dec == a * b, $"{Environment.NewLine}{Environment.NewLine}" +
                                                  $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                                  $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b * a   : {b * a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"bxa_dec : {bxa_dec}");

                    // Division
                    var adb_enc = decryptAlgorithm.Divide(a_enc, b_enc);
                    var adb_dec = decryptAlgorithm.DecryptData(adb_enc);
                    Assert.True(adb_dec == new BigFraction(a, b),
                                                  $"{Environment.NewLine}{Environment.NewLine}" +
                                                  $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                                  $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a / b   : {new BigFraction(a, b)}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"adb_dec : {adb_dec}");

                    var bda_enc = decryptAlgorithm.Divide(b_enc, a_enc);
                    var bda_dec = decryptAlgorithm.DecryptData(bda_enc);
                    Assert.True(bda_dec == new BigFraction(b, a),
                                                  $"{Environment.NewLine}{Environment.NewLine}" +
                                                  $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                                  $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b / a   : {new BigFraction(b, a)}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"bda_dec : {bda_dec}");

                    algorithm.Dispose();
                    encryptAlgorithm.Dispose();
                    decryptAlgorithm.Dispose();
                }
            }
        }

    }
}
