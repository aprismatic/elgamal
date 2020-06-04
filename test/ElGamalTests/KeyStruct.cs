using Aprismatic.ElGamalExt;
using Xunit;
using Xunit.Abstractions;

namespace ElGamalTests
{
    public class KeyStruct
    {
        private readonly ITestOutputHelper output;

        public KeyStruct(ITestOutputHelper output)
        {
            this.output = output;
        }

        [Fact(DisplayName = "Lengths")]
        public void TestLengths()
        {
            for (var i = 0; i < Globals.iterations; i++)
            {
                for (var keySize = 384; keySize <= 1088; keySize += 8)
                {
                    var algorithm = new ElGamal(keySize);
                    var prms = algorithm.ExportParameters(false);

                    Assert.Equal(algorithm.KeySize / 8, prms.P.Length);

                    algorithm.Dispose();
                }
            }
        }
    }
}
