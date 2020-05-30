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
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();

        public FracEncDec(ITestOutputHelper output)
        {
            this.output = output;
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
                for (var keySize = 384; keySize <= 1088; keySize += 8)
                {
                    var algorithm = new ElGamal(keySize);

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
