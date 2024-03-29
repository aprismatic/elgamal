﻿using System;
using System.Numerics;
using System.Reflection.Metadata;
using System.Security.Cryptography;
using Aprismatic;
using Aprismatic.ElGamal;
using Xunit;
using Xunit.Abstractions;

namespace ElGamalTests
{
    public class PlaintextOperations : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new();
        private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

        private readonly int minKeySize;
        private readonly int maxKeySize;
        private readonly int step;

        public PlaintextOperations(ITestOutputHelper output)
        {
            this.output = output;

            using var tmpElG = new ElGamal(512, 0);
            minKeySize = tmpElG.LegalKeySizes[0].MinSize;
            maxKeySize = tmpElG.LegalKeySizes[0].MaxSize;
            step = (maxKeySize - minKeySize) / (Globals.KeySteps - 1);
        }

        public void Dispose() => rng.Dispose();

        [Fact(DisplayName = "PLAINTEXT (MUL/DIV, +-)")]
        public void TestPlaintextMulDiv()
        {
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
                    } while (a <= 0);

                    do
                    {
                        var n = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits / 4), rng);
                        var d = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits / 4), rng);
                        b = new BigFraction(n, d);
                    } while (b <= 0);

                    if (rnd.Next() % 2 == 0) // randomly change signs
                        a = -a;
                    if (rnd.Next() % 2 == 0)
                        b = -b;

                    var a_enc = encryptAlgorithm.EncryptData(a);


                    // Multiplication
                    var axb_enc = decryptAlgorithm.PlaintextMultiply(a_enc, b);
                    var axb_dec = decryptAlgorithm.DecryptData(axb_enc);
                    Assert.True(axb_dec == a * b,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                        $"a * b   : {a * b}{Environment.NewLine}{Environment.NewLine}" +
                        $"axb_dec : {axb_dec}");

                    var ax1_enc = decryptAlgorithm.PlaintextMultiply(a_enc, BigFraction.One);
                    var ax1_dec = decryptAlgorithm.DecryptData(ax1_enc);
                    Assert.True(ax1_dec == a,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"b       : {BigFraction.One}{Environment.NewLine}{Environment.NewLine}" +
                        $"a * b   : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"ax1_dec : {ax1_dec}");

                    var ax0_enc = decryptAlgorithm.PlaintextMultiply(a_enc, BigFraction.Zero);
                    var ax0_dec = decryptAlgorithm.DecryptData(ax0_enc);
                    Assert.True(ax0_dec == BigFraction.Zero,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"b       : {BigFraction.Zero}{Environment.NewLine}{Environment.NewLine}" +
                        $"a * b   : {BigFraction.Zero}{Environment.NewLine}{Environment.NewLine}" +
                        $"ax0_dec : {ax0_dec}");

                    var axm1_enc = decryptAlgorithm.PlaintextMultiply(a_enc, BigFraction.MinusOne);
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
                    var adb_enc = decryptAlgorithm.PlaintextDivide(a_enc, b);
                    var adb_dec = decryptAlgorithm.DecryptData(adb_enc);
                    Assert.True(adb_dec == a / b,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                        $"a / b   : {a / b}{Environment.NewLine}{Environment.NewLine}" +
                        $"adb_dec : {adb_dec}");

                    var ad1_enc = decryptAlgorithm.PlaintextMultiply(a_enc, BigFraction.One);
                    var ad1_dec = decryptAlgorithm.DecryptData(ad1_enc);
                    Assert.True(ad1_dec == a,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"b       : {BigFraction.One}{Environment.NewLine}{Environment.NewLine}" +
                        $"a / b   : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"ax1_dec : {ad1_dec}");

                    var adm1_enc = decryptAlgorithm.PlaintextMultiply(a_enc, BigFraction.MinusOne);
                    var adm1_dec = decryptAlgorithm.DecryptData(adm1_enc);
                    Assert.True(adm1_dec == -a,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"b       : {BigFraction.MinusOne}{Environment.NewLine}{Environment.NewLine}" +
                        $"a / b   : {-a}{Environment.NewLine}{Environment.NewLine}" +
                        $"axm1_dec : {adm1_dec}");
                }
            }
        }

        [Fact(DisplayName = "PLAINTEXT POW")]
        public void TestPlaintextPow()
        {
            for (var i = 0; i < Globals.Iterations; i++)
            {
                for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
                {
                    using var algorithm = new ElGamal(keySize, 0);

                    using var encryptAlgorithm = new ElGamal(algorithm.ToXmlString(false));
                    using var decryptAlgorithm = new ElGamal(algorithm.ToXmlString(true));

                    var n = new BigInteger().GenRandomBits(rnd.Next(1, 12), rng);
                    var d = new BigInteger().GenRandomBits(rnd.Next(1, 12), rng);
                    var a = new BigFraction(n, d);

                    var b = rnd.Next(1, 10);

                    var a_enc = encryptAlgorithm.EncryptData(a);

                    var apb_enc = decryptAlgorithm.PlaintextPow(a_enc, b);
                    var apb_dec = decryptAlgorithm.DecryptData(apb_enc);
                    var res = new BigFraction(BigInteger.Pow(a.Numerator, b), BigInteger.Pow(a.Denominator,b));
                    Assert.True(apb_dec == res,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                        $"a ^ b   : {res}{Environment.NewLine}{Environment.NewLine}" +
                        $"apb_dec : {apb_dec}");
                }
            }

            // Test overflow
            for (var i = 0; i < Globals.Iterations; i++)
            {
                using var algorithm = new ElGamal(512, 0);

                var a = new BigInteger().GenRandomBits(rnd.Next(16, 24), rng);

                var P = algorithm.P;
                var big_exp = BigInteger.Pow(2, 128) + 5;

                var bi_block_length = algorithm.CiphertextLength / 2;
                var a_enc = new byte[bi_block_length];
                algorithm.Encryptor.ProcessBigInteger(a, a_enc);

                var a_enc_exp = new byte[bi_block_length];
                var a_enc_exp_sp = a_enc_exp.AsSpan();
                algorithm.PlaintextPowBigInteger(a_enc, big_exp, a_enc_exp_sp);

                var bi_part_length = bi_block_length / 2;
                var a_exp_dec =
                    algorithm.Decryptor.ProcessByteBlock(a_enc_exp_sp[..bi_part_length],
                        a_enc_exp_sp[bi_part_length..]);

                var expect = BigInteger.ModPow(a, big_exp, P);

                Assert.True(expect == a_exp_dec,
                    $"{Environment.NewLine}{Environment.NewLine}" +
                    $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                    $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                    $"a       : {a}{Environment.NewLine}" +
                    $"big_exp : {big_exp}{Environment.NewLine}" +
                    $"expect  : {expect}{Environment.NewLine}" +
                    $"actual  : {a_exp_dec}");
            }

            // TODO: Add tests for 0^x, x^0, 1^x, x^1, 0^1, 1^0
            // TODO: Add tests for -2^2 (negative numbers < -2 will cause overflow on smaller key sizes with mxptbits = 128)
        }

        [Fact(DisplayName = "PLAINTEXT POW BY ZERO")]
        public void TestPlaintextPowZero()
        {
            for (var i = 0; i < Globals.Iterations; i++)
            {
                for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
                {
                    using var algorithm = new ElGamal(keySize, 0);

                    using var encryptAlgorithm = new ElGamal(algorithm.ToXmlString(false));
                    using var decryptAlgorithm = new ElGamal(algorithm.ToXmlString(true));

                    var n = new BigInteger().GenRandomBits(rnd.Next(1, 12), rng);
                    var d = new BigInteger().GenRandomBits(rnd.Next(1, 12), rng);
                    var a = new BigFraction(n, d);

                    n = new BigInteger().GenRandomBits(rnd.Next(1, 12), rng);
                    d = new BigInteger().GenRandomBits(rnd.Next(1, 12), rng);
                    var b = new BigFraction(n, d);
                    b = -b;

                    var a_enc = encryptAlgorithm.EncryptData(a);
                    var b_enc = encryptAlgorithm.EncryptData(b);

                    var ap0_enc = decryptAlgorithm.PlaintextPow(a_enc, 0);
                    var bp0_enc = decryptAlgorithm.PlaintextPow(b_enc, 0);
                    var ap0_dec = decryptAlgorithm.DecryptData(ap0_enc);
                    var bp0_dec = decryptAlgorithm.DecryptData(bp0_enc);

                    Assert.True(ap0_dec == 1,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}" +
                        $"ap0_dec : {ap0_dec}");

                    Assert.True(bp0_dec == 1,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {b}{Environment.NewLine}" +
                        $"ap0_dec : {bp0_dec}");
                }
            }
        }

        [Fact(DisplayName = "PLAINTEXT POW BY NEGATIVE")]
        public void TestPlaintextPowNegative()
        {
            for (var i = 0; i < Globals.Iterations; i++)
            {
                for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
                {
                    using var algorithm = new ElGamal(keySize, 0);

                    using var encryptAlgorithm = new ElGamal(algorithm.ToXmlString(false));
                    using var decryptAlgorithm = new ElGamal(algorithm.ToXmlString(true));

                    var n = new BigInteger().GenRandomBits(rnd.Next(1, 12), rng);
                    var d = new BigInteger().GenRandomBits(rnd.Next(1, 12), rng);
                    var a = new BigFraction(n, d);

                    n = new BigInteger().GenRandomBits(rnd.Next(1, 12), rng);
                    d = new BigInteger().GenRandomBits(rnd.Next(1, 12), rng);
                    var b = new BigFraction(n, d);
                    b = -b;

                    var pow = new BigInteger().GenRandomBits(rnd.Next(2,3), rng);
                    pow = -pow;

                    var a_enc = encryptAlgorithm.EncryptData(a);
                    var b_enc = encryptAlgorithm.EncryptData(b);

                    var ap0_enc = decryptAlgorithm.PlaintextPow(a_enc, pow);
                    var bp0_enc = decryptAlgorithm.PlaintextPow(b_enc, pow);
                    var ap0_dec = decryptAlgorithm.DecryptData(ap0_enc);
                    var bp0_dec = decryptAlgorithm.DecryptData(bp0_enc);

                    Assert.True(ap0_dec == new BigFraction(BigInteger.Pow(a.Denominator, (int)(-pow)), BigInteger.Pow(a.Numerator, (int)(-pow))),
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}" +
                        $"ap0_dec : {ap0_dec}");

                    Assert.True(ap0_dec == new BigFraction(BigInteger.Pow(b.Denominator, (int)(-pow)), BigInteger.Pow(b.Numerator, (int)(-pow))),
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {b}{Environment.NewLine}" +
                        $"ap0_dec : {bp0_dec}");
                }
            }
        }
    }
}
