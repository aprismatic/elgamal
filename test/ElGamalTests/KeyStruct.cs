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

            // invalid key sizes
            for (var i = 0; i < Globals.Iterations; i++)
            {
                var keySize = minKeySize - 1;
                Assert.Throws<ArgumentException>(() => new ElGamal(keySize));
                var p = BigInteger.One.GenRandomBits(keySize, rng);
                Assert.Throws<ArgumentException>(() => new ElGamal(p));

                keySize = maxKeySize + 1;
                Assert.Throws<ArgumentException>(() => new ElGamal(keySize));
                p = BigInteger.One.GenRandomBits(keySize, rng);
                Assert.Throws<ArgumentException>(() => new ElGamal(p));

                keySize = minKeySize + 1;
                Assert.Throws<ArgumentException>(() => new ElGamal(keySize));
                p = BigInteger.One.GenRandomBits(keySize, rng);
                Assert.Throws<ArgumentException>(() => new ElGamal(p));

                keySize = maxKeySize - 1;
                Assert.Throws<ArgumentException>(() => new ElGamal(keySize));
                p = BigInteger.One.GenRandomBits(keySize, rng);
                Assert.Throws<ArgumentException>(() => new ElGamal(p));
            }

            // existing prime
            for (var i = 0; i < Globals.Iterations; i++)
            {
                var p = BigInteger.One;
                do
                    p = BigInteger.One.GenPseudoPrime(minKeySize, 8, rng);
                while (((p-1)/2).IsProbablePrime(8, rng)); // make p NOT a safe prime

                Assert.Throws<ArgumentException>(() => new ElGamal(p));

                p = p.GenSafePseudoPrime(minKeySize, 8, rng);
                var eg = new ElGamal(p);

                Assert.Equal(eg.P, p);
                Assert.Equal(eg.KeySize, p.BitCount());
                Assert.Equal(p.BitCount(), eg.PLength * 8);

                var prms = eg.ExportParameters(true);
                var X = new BigInteger(prms.X);
                Assert.True(X > 1);
                Assert.True(X < p - 1);

                Assert.Throws<ArgumentException>(() => new ElGamal(p + 1)); // not a prime
            }
        }
    }
}
