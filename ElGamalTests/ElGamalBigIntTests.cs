using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Numerics;
using ElGamalExt.BigInt;
using System.Text;
using System.Security.Cryptography;
using System.Linq;

namespace ElGamalTests
{
    [TestClass]
    public class ElGamalBigInt
    {
        [TestMethod]
        public void TestModInverse()
        {
            {
                var a = new BigInteger();
                BigInteger.TryParse("470782681346529800216759025446747092045188631141622615445464429840250748896490263346676188477401449398784352124574498378830506322639352584202116605974693692194824763263949618703029846313252400361025245824301828641617858127932941468016666971398736792667282916657805322080902778987073711188483372360907612588995664533157503380846449774089269965646418521613225981431666593065726252482995754339317299670566915780168", out a);
                var b = a.modInverse(new BigInteger(1000000007));
                Assert.AreEqual("736445995", b.ToString());

                b = a.modInverse(new BigInteger(1999));
                Assert.AreEqual("1814", b.ToString());

                var isExceptionRaised = false;
            }

            for (var i = 0; i < 9999; i++)
            {
                var rnd = new Random();
                var bi = new BigInteger();
                bi = bi.genRandomBits(rnd.Next(1, 1024), new RNGCryptoServiceProvider());

                var mod = bi.genRandomBits(rnd.Next(1, 128), new RNGCryptoServiceProvider());
                while ((BigInteger.GreatestCommonDivisor(bi, mod) != 1) || (mod <= 1))
                {
                    mod = mod.genRandomBits(rnd.Next(1, 128), new RNGCryptoServiceProvider());
                }

                var inv = bi.modInverse(mod);

                Assert.AreEqual(bi != 0 ? 1 : 0, (bi * inv) % mod, $"{Environment.NewLine}bi:  {bi}{Environment.NewLine}mod: {mod}{Environment.NewLine}inv: {inv}");
            }
        }

        [TestMethod()]
        public void TestIsProbablePrime()
        {
            Assert.IsFalse(BigInteger.Zero.isProbablePrime(10));
            Assert.IsFalse(BigInteger.One.isProbablePrime(10));

            for (var i = 2; i < 2000; i++)
            {
                var res = (new BigInteger(i)).isProbablePrime(10);
                Assert.AreEqual(ElGamalBigIntegerFunctions.primesBelow2000.Contains(i),
                                res,
                                $"{i} is prime is {ElGamalBigIntegerFunctions.primesBelow2000.Contains(i)} but was evaluated as {res}");
            }

            foreach (var p in new[] {633910111, 838041647, 15485863, 452930477, 28122569887267, 29996224275833 })
            {
                Assert.IsTrue((new BigInteger(p)).isProbablePrime(10));
            }

            foreach (var p in new[] { 398012025725459, 60030484763 })
            {
                Assert.IsFalse((new BigInteger(p)).isProbablePrime(50));
            }
        }

        [TestMethod]
        public void TestSecuredGenRandomBits()
        {
            var rng = new RNGCryptoServiceProvider();
            var rand = new Random();

            for (var i = 0; i < 999999; i++)
            { // Test < 32 bits
                var bi = new BigInteger();

                bi = bi.genRandomBits(rand.Next(1, 33), rng);

                var bytes = bi.ToByteArray();
                var new_bytes = new byte[4];
                Array.Copy(bytes, new_bytes, bytes.Length);

                Assert.IsTrue(BitConverter.ToUInt32(new_bytes, 0) < (Math.Pow(2, 32) - 1));
            }

            // Test on random number of bits
            for (var i = 0; i < 999999; i++)
            {
                var bi = new BigInteger();
                var bits = rand.Next(1, 70 * 32 + 1);
                bi = bi.genRandomBits(bits, rng);
                Assert.IsTrue(bits >= bi.bitCount());
                Assert.IsTrue(bi >= 0);
            }

            for (var i = 0; i < 9999; i++)
            { // Test lower boudary value
                var bi = new BigInteger();

                bi = bi.genRandomBits(1, rng);
                Assert.IsTrue(bi.ToByteArray()[0] == 1 || bi.ToByteArray()[0] == 0);
            }
        }

        [TestMethod]
        public void TestGenPseudoPrime()
        {
            var bi = new BigInteger();
            var rng = new RNGCryptoServiceProvider();
            var rand = new Random();

            // Test arbitrary values 
            for (var i = 0; i < 30; i++)
            {
                var prime = bi.genPseudoPrime(rand.Next(1, 512), 2, rng);

                foreach (var pr in ElGamalBigIntegerFunctions.primesBelow2000)
                {
                    Assert.IsTrue(prime % pr != 0);
                }
            }
        }
    }
}
