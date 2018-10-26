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

        private readonly Random rnd = new Random();
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();

        public IntEncDec(ITestOutputHelper output)
        {
            this.output = output;
        }

        public void Dispose()
        {
            rng.Dispose();
        }

        [Fact(DisplayName = "INT (ENC/DEC, +-)")]
        public void TestRandomBigInteger()
        {
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

                    var z = new BigInteger();

                    z = z.GenRandomBits(rnd.Next(1, algorithm.KeyStruct.getMaxPlaintextBits() - 1), rng);
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
