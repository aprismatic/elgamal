using System;
using System.Numerics;
using System.Security.Cryptography;
using Aprismatic;
using Aprismatic.ElGamalExt;
using Xunit;
using Xunit.Abstractions;

namespace ElGamalTests
{
    public class FracEncDec : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new Random();
        private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

        private readonly int minKeySize;
        private readonly int maxKeySize;
        private readonly int step;

        public FracEncDec(ITestOutputHelper output)
        {
            this.output = output;

            using var tmpElG = new ElGamal(512, 0);
            minKeySize = tmpElG.LegalKeySizes[0].MinSize;
            maxKeySize = tmpElG.LegalKeySizes[0].MaxSize;
            step = (maxKeySize - minKeySize) / tmpElG.LegalKeySizes[0].SkipSize;
        }

        public void Dispose()
        {
            rng.Dispose();
        }

        [Fact(DisplayName = "FRAC (ENC/DEC, +-)")]
        public void TestRandomBigFraction()
        {
            for (var i = 0; i < Globals.iterations; i++)
            {
                for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
                {
                    var algorithm = new ElGamal(keySize, 0);

                    var encryptAlgorithm = new ElGamal(algorithm.ToXmlString(false));

                    var decryptAlgorithm = new ElGamal(algorithm.ToXmlString(true));

                    var n = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits - 1), rng);
                    var d = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits - 1), rng);
                    var f = new BigFraction(n, d);
                    if (rnd.Next() % 2 == 0) // random sign
                        f *= -1;

                    var f_enc = encryptAlgorithm.EncryptData(f);
                    var f_dec = decryptAlgorithm.DecryptData(f_enc);

                    Assert.True(f == f_dec, $"{Environment.NewLine}{Environment.NewLine}" +
                                            $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                            $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                            $"f     : {f}{Environment.NewLine}{Environment.NewLine}" +
                                            $"f_dec : {f_dec}");

                    algorithm.Dispose();
                    encryptAlgorithm.Dispose();
                    decryptAlgorithm.Dispose();
                }
            }
        }
    }
}
