﻿using System;
using System.Numerics;
using System.Security.Cryptography;
using Aprismatic;
using Aprismatic.ElGamal;
using Xunit;
using Xunit.Abstractions;

namespace ElGamalTests
{
    public class FracMulDiv : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

        private readonly int minKeySize;
        private readonly int maxKeySize;
        private readonly int step;

        public FracMulDiv(ITestOutputHelper output)
        {
            this.output = output;

            using var tmpElG = new ElGamal(512, 0);
            minKeySize = tmpElG.LegalKeySizes[0].MinSize;
            maxKeySize = tmpElG.LegalKeySizes[0].MaxSize;
            step = (maxKeySize - minKeySize) / (Globals.KeySteps - 1);
        }

        public void Dispose() => rng.Dispose();

        [Fact(DisplayName = "FRAC (MUL/DIV, +-)")]
        public void TestMultiplication_BatchFrac()
        {
            var rnd = new Random();
            var rng = RandomNumberGenerator.Create();

            for (var i = 0; i < Globals.Iterations; i++)
            {
                for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
                {
                    using var algorithm = new ElGamal(keySize, 0);
                    using var encryptAlgorithm = new ElGamal(algorithm.ToXmlString(false));
                    using var decryptAlgorithm = new ElGamal(algorithm.ToXmlString(true));

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
                    Assert.True(bxa_dec == b * a, $"{Environment.NewLine}{Environment.NewLine}" +
                                                  $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                                  $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b * a   : {b * a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"bxa_dec : {bxa_dec}");

                    // Division
                    var adb_enc = decryptAlgorithm.Divide(a_enc, b_enc);
                    var adb_dec = decryptAlgorithm.DecryptData(adb_enc);
                    Assert.True(adb_dec == a / b, $"{Environment.NewLine}{Environment.NewLine}" +
                                                  $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                                  $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a / b   : {a / b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"adb_dec : {adb_dec}");

                    var bda_enc = decryptAlgorithm.Divide(b_enc, a_enc);
                    var bda_dec = decryptAlgorithm.DecryptData(bda_enc);
                    Assert.True(bda_dec == b / a, $"{Environment.NewLine}{Environment.NewLine}" +
                                                  $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                                  $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b / a   : {b / a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"bda_dec : {bda_dec}");
                }
            }
        }
    }
}
