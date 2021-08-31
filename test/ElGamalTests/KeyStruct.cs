using System.Numerics;
using Aprismatic;
using Aprismatic.ElGamalExt;
using Xunit;
using Xunit.Abstractions;

namespace ElGamalTests
{
    public class KeyStruct
    {
        private readonly ITestOutputHelper output;

        private readonly int minKeySize;
        private readonly int maxKeySize;
        private readonly int step;

        public KeyStruct(ITestOutputHelper output)
        {
            this.output = output;

            using var tmpElG = new ElGamal(512, 0);
            minKeySize = tmpElG.LegalKeySizes[0].MinSize;
            maxKeySize = tmpElG.LegalKeySizes[0].MaxSize;
            step = (maxKeySize - minKeySize) / tmpElG.LegalKeySizes[0].SkipSize;
        }

        [Fact(DisplayName = "Lengths")]
        public void TestLengths()
        {
            for (var i = 0; i < Globals.iterations; i++)
            {
                for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
                {
                    using var algorithm = new ElGamal(keySize, 0);
                    var prms = algorithm.ExportParameters(false);

                    var P = new BigInteger(prms.P);
                    Assert.Equal(algorithm.KeySize, P.BitCount());

                    algorithm.Dispose();
                }
            }
        }
    }
}
