using System;
using System.Security.Cryptography;
using Aprismatic.ElGamalExt;
using Xunit;
using Xunit.Abstractions;

namespace ElGamalTests
{
    public class KeyStruct : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new Random();
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();

        public KeyStruct(ITestOutputHelper output)
        {
            this.output = output;
        }

        public void Dispose()
        {
            rng.Dispose();
        }

        [Fact(DisplayName = "Lengths")]
        public void TestLengths()
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

                    Assert.Equal(algorithm.KeySize / 8, algorithm.KeyStruct.getPLength());

                    algorithm.Dispose();
                }
            }
        }
    }
}
