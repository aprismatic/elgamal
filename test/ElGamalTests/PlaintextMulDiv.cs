using System;
using System.Numerics;
using System.Security.Cryptography;
using Aprismatic;
using Aprismatic.ElGamalExt;
using Xunit;
using Xunit.Abstractions;

namespace ElGamalTests
{
    public class PlaintextMulDiv : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new Random();
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();

        public PlaintextMulDiv(ITestOutputHelper output)
        {
            this.output = output;
        }

        public void Dispose()
        {
            rng.Dispose();
        }

        [Fact(DisplayName = "PLAINTEXT (MUL/DIV, +-)")]
        public void TestPlaintextOperations()
        {
            var rnd = new Random();
            var rng = new RNGCryptoServiceProvider();

            for (var i = 0; i < Globals.iterations; i++)
            {
                for (var keySize = 384; keySize <= 1088; keySize += 8)
                {
                    var algorithm = new ElGamal(keySize);

                    var encryptAlgorithm = new ElGamal(algorithm.ToXmlString(false));
                    var decryptAlgorithm = new ElGamal(algorithm.ToXmlString(true));

                    BigFraction a, b;
                    do
                    {
                        var n = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits / 4), rng);
                        var d = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits / 4), rng);
                        a = new BigFraction(n, d);
                    } while (a == 0);
                    do
                    {
                        var n = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits / 4), rng);
                        var d = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits / 4), rng);
                        b = new BigFraction(n, d);
                    } while (b == 0);

                    if (rnd.Next() % 2 == 0) // randomly change signs
                        a = -a;
                    if (rnd.Next() % 2 == 0)
                        b = -b;

                    var a_enc = encryptAlgorithm.EncryptData(a);


                    // Multiplication
                    var axb_enc = decryptAlgorithm.MultiplyByPlaintext(a_enc, b);
                    var axb_dec = decryptAlgorithm.DecryptData(axb_enc);
                    Assert.True(axb_dec == a * b,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                        $"a * b   : {a * b}{Environment.NewLine}{Environment.NewLine}" +
                        $"axb_dec : {axb_dec}");

                    var ax1_enc = decryptAlgorithm.MultiplyByPlaintext(a_enc, BigFraction.One);
                    var ax1_dec = decryptAlgorithm.DecryptData(ax1_enc);
                    Assert.True(ax1_dec == a,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"b       : {BigFraction.One}{Environment.NewLine}{Environment.NewLine}" +
                        $"a * b   : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"ax1_dec : {ax1_dec}");

                    var ax0_enc = decryptAlgorithm.MultiplyByPlaintext(a_enc, BigFraction.Zero);
                    var ax0_dec = decryptAlgorithm.DecryptData(ax0_enc);
                    Assert.True(ax0_dec == BigFraction.Zero,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"b       : {BigFraction.Zero}{Environment.NewLine}{Environment.NewLine}" +
                        $"a * b   : {BigFraction.Zero}{Environment.NewLine}{Environment.NewLine}" +
                        $"ax0_dec : {ax0_dec}");

                    var axm1_enc = decryptAlgorithm.MultiplyByPlaintext(a_enc, BigFraction.MinusOne);
                    var axm1_dec = decryptAlgorithm.DecryptData(axm1_enc);
                    Assert.True(axm1_dec == -a,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"b       : {BigFraction.MinusOne}{Environment.NewLine}{Environment.NewLine}" +
                        $"a * b   : {-a}{Environment.NewLine}{Environment.NewLine}" +
                        $"axm1_dec : {axm1_dec}");

                    // Division
                    var adb_enc = decryptAlgorithm.DivideByPlaintext(a_enc, b);
                    var adb_dec = decryptAlgorithm.DecryptData(adb_enc);
                    Assert.True(adb_dec == a / b,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                        $"a / b   : {a / b}{Environment.NewLine}{Environment.NewLine}" +
                        $"adb_dec : {adb_dec}");

                    var ad1_enc = decryptAlgorithm.MultiplyByPlaintext(a_enc, BigFraction.One);
                    var ad1_dec = decryptAlgorithm.DecryptData(ad1_enc);
                    Assert.True(ad1_dec == a,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"b       : {BigFraction.One}{Environment.NewLine}{Environment.NewLine}" +
                        $"a / b   : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"ax1_dec : {ad1_dec}");

                    var adm1_enc = decryptAlgorithm.MultiplyByPlaintext(a_enc, BigFraction.MinusOne);
                    var adm1_dec = decryptAlgorithm.DecryptData(adm1_enc);
                    Assert.True(adm1_dec == -a,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"b       : {BigFraction.MinusOne}{Environment.NewLine}{Environment.NewLine}" +
                        $"a / b   : {-a}{Environment.NewLine}{Environment.NewLine}" +
                        $"axm1_dec : {adm1_dec}");

                    algorithm.Dispose();
                    encryptAlgorithm.Dispose();
                    decryptAlgorithm.Dispose();
                }
            }
        }
    }
}
