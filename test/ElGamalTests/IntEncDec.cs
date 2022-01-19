using System;
using System.Numerics;
using System.Security.Cryptography;
using Aprismatic;
using Aprismatic.ElGamalExt;
using Xunit;
using Xunit.Abstractions;

namespace ElGamalTests
{
    public class IntEncDec : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new();
        private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

        private readonly int minKeySize;
        private readonly int maxKeySize;
        private readonly int step;

        public IntEncDec(ITestOutputHelper output)
        {
            this.output = output;

            using var tmpElG = new ElGamal(512, 0);
            minKeySize = tmpElG.LegalKeySizes[0].MinSize;
            maxKeySize = tmpElG.LegalKeySizes[0].MaxSize;
            step = (maxKeySize - minKeySize) / (Globals.KeySteps - 1);
        }

        public void Dispose() => rng.Dispose();

        [Fact(DisplayName = "INT (ENC/DEC, +-)")]
        public void TestRandomBigInteger()
        {
            for (var i = 0; i < Globals.Iterations; i++)
            {
                for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
                {
                    var algorithm = new ElGamal(keySize, 0);

                    var encryptAlgorithm = new ElGamal(algorithm.ToXmlString(false));

                    var decryptAlgorithm = new ElGamal(algorithm.ToXmlString(true));

                    var z = new BigInteger();

                    z = z.GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits - 1), rng);
                    if (rnd.Next() % 2 == 0) // random sign
                        z = -z;

                    var z_enc = encryptAlgorithm.EncryptData(z);
                    var z_dec = decryptAlgorithm.DecryptData(z_enc);

                    Assert.True(z == z_dec, $"{Environment.NewLine}{Environment.NewLine}" +
                                            $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                            $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                            $"z     : {z}{Environment.NewLine}{Environment.NewLine}" +
                                            $"z_dec : {z_dec}");

                    algorithm.Dispose();
                    encryptAlgorithm.Dispose();
                    decryptAlgorithm.Dispose();
                }
            }
        }
    }
}
