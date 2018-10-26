using System;
using System.Numerics;
using System.Security.Cryptography;
using Aprismatic;
using Aprismatic.ElGamalExt;
using Xunit;
using Xunit.Abstractions;

namespace ElGamalTests
{
    public class EdgeCases : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new Random();
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();

        public EdgeCases(ITestOutputHelper output)
        {
            this.output = output;
        }

        public void Dispose()
        {
            rng.Dispose();
        }

        [Fact(DisplayName = "Zero")]
        public void TestZero()
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

                var z = new BigInteger(0);
                var r = new BigInteger(rnd.Next(1, 65536));

                var z_enc = encryptAlgorithm.EncryptData(z);
                var z_dec = decryptAlgorithm.DecryptData(z_enc);

                Assert.Equal(z, z_dec);

                var r_enc = encryptAlgorithm.EncryptData(r);
                var zxr_enc = decryptAlgorithm.Multiply(z_enc, r_enc);
                var rxz_enc = decryptAlgorithm.Multiply(r_enc, z_enc);
                var zdr_enc = decryptAlgorithm.Divide(z_enc, r_enc);
                var zxr = decryptAlgorithm.DecryptData(zxr_enc);
                var rxz = decryptAlgorithm.DecryptData(rxz_enc);
                var zdr = decryptAlgorithm.DecryptData(zdr_enc);

                Assert.Equal(0, zxr);
                Assert.Equal(0, rxz);
                Assert.Equal(0, zdr);

                algorithm.Dispose();
                encryptAlgorithm.Dispose();
                decryptAlgorithm.Dispose();
            }
        }

        [Fact(DisplayName = "One")]
        public void TestOne()
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

                var o = new BigInteger(1);
                var r = new BigInteger(rnd.Next(2, 65536));

                var o_enc = encryptAlgorithm.EncryptData(o);
                var o_dec = decryptAlgorithm.DecryptData(o_enc);

                Assert.Equal(o, o_dec);

                var r_enc = encryptAlgorithm.EncryptData(r);
                var oxr_enc = decryptAlgorithm.Multiply(o_enc, r_enc);
                var rxo_enc = decryptAlgorithm.Multiply(r_enc, o_enc);
                var odr_enc = decryptAlgorithm.Divide(o_enc, r_enc);
                var rdo_enc = decryptAlgorithm.Divide(r_enc, o_enc);
                var oxr = decryptAlgorithm.DecryptData(oxr_enc);
                var rxo = decryptAlgorithm.DecryptData(rxo_enc);
                var odr = decryptAlgorithm.DecryptData(odr_enc);
                var rdo = decryptAlgorithm.DecryptData(rdo_enc);

                Assert.Equal(r, oxr);
                Assert.Equal(r, rxo);
                Assert.Equal(new BigFraction(1, r), odr);
                Assert.Equal(r, rdo);

                algorithm.Dispose();
                encryptAlgorithm.Dispose();
                decryptAlgorithm.Dispose();
            }
        }

        [Fact(DisplayName = "Edge values")]
        public void MinAndMaxValues()
        {
            var max = BigInteger.Pow(2, 127) - 1; // should work
            var max_plus = max + 1; // should throw
            var min = -max; // should work
            var min_minus = min - 1; // should throw

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


                // MAX
                var max_enc = encryptAlgorithm.EncryptData(max);
                var max_dec = decryptAlgorithm.DecryptData(max_enc);
                Assert.True(max_dec == max, $"{Environment.NewLine}{Environment.NewLine}" +
                                            $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                            $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                            $"max     : {max}{Environment.NewLine}{Environment.NewLine}" +
                                            $"max_dec : {max_dec}");

                // MIN
                var min_enc = encryptAlgorithm.EncryptData(min);
                var min_dec = decryptAlgorithm.DecryptData(min_enc);
                Assert.True(min_dec == min, $"{Environment.NewLine}{Environment.NewLine}" +
                                            $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                            $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                            $"min     : {min}{Environment.NewLine}{Environment.NewLine}" +
                                            $"min_dec : {min_dec}");

                // MAX + 1
                Assert.Throws<ArgumentException>(() => encryptAlgorithm.EncryptData(max_plus));

                // MIN - 1
                Assert.Throws<ArgumentException>(() => encryptAlgorithm.EncryptData(min_minus));

                algorithm.Dispose();
                encryptAlgorithm.Dispose();
                decryptAlgorithm.Dispose();
            }
        }
    }
}
