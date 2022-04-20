using System;
using System.Numerics;
using System.Security.Cryptography;
using Aprismatic;
using Aprismatic.ElGamal;
using Xunit;
using Xunit.Abstractions;

namespace ElGamalTests
{
    public class KeyStruct : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

        private readonly int minKeySize;
        private readonly int maxKeySize;
        private readonly int step;

        public KeyStruct(ITestOutputHelper output)
        {
            this.output = output;

            using var tmpElG = new ElGamal(512, 0);
            minKeySize = tmpElG.LegalKeySizes[0].MinSize;
            maxKeySize = tmpElG.LegalKeySizes[0].MaxSize;
            step = (maxKeySize - minKeySize) / (Globals.KeySteps - 1);
        }

        public void Dispose() => rng.Dispose();

        [Fact(DisplayName = "KeyStruct")]
        public void TestKeyStruct()
        {
            for (var i = 0; i < Globals.Iterations; i++)
            {
                var keySize = minKeySize; // generating safe primes for larger keys is VERY slow

                using var algorithm = new ElGamal(keySize, 0);
                var prms = algorithm.ExportParameters(true);

                var P = new BigInteger(prms.P);
                Assert.Equal(algorithm.P, P);
                Assert.Equal(algorithm.KeySize, P.BitCount());
                Assert.Equal(P.BitCount(), algorithm.PLength * 8);
                Assert.True(P.IsProbablePrime(16, rng));
                Assert.True(((P - 1) / 2).IsProbablePrime(16, rng));

                var X = new BigInteger(prms.X);
                Assert.True(X > 1);
                Assert.True(X < P - 1);
            }
        }
    }
}
