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
        public void TestBigInt()
        {
            var r = new Random();
            for (int i = 0; i < 9999; i++)
            {
                int length = r.Next(Int32.MaxValue); // TODO: 70 - current maxLength, remove hardcoded value

                BigInteger o = new BigInteger(length);
                BigInteger p = new BigInteger(o.getBytes());

                byte[] o_byte = o.getBytes();
                byte[] p_byte = p.getBytes();

                Assert.AreEqual(o, p);
            }
        }


        [TestMethod]
        public void TestGetBytes()
        {
            { // Randomized tests
                var r = new Random();

                for (int j = 0; j < 512; j++)
                {
                    var length = r.Next(1, 256);
                    var byte_array = new byte[length];
                    r.NextBytes(byte_array);
                    if (byte_array[length-1] == 0 || byte_array[length - 1] == 255)
                        byte_array[length - 1] = (byte)r.Next(1, 255);

                    var bi = new BigInteger(byte_array);

                    var bytes_got_back = bi.getBytes();

                    Assert.AreEqual(byte_array.Length, bytes_got_back.Length);

                    for (var i = 0; i < byte_array.Length; i++)
                        Assert.AreEqual(bytes_got_back[i], byte_array[i]);
                }
            }

            { // Special case - zero
                var z = new BigInteger(0);

                var zero_bytes = z.getBytes();

                Assert.AreNotEqual(zero_bytes.Length, 0);
                Assert.AreEqual(zero_bytes[0], (byte)0);
            }
        }

        [TestMethod]
        public void TestGCD()
        {
            BigInteger bi1, bi2;
            int val1, val2;
            Random rand = new Random();

            for (int i = 0; i < 100; i++)
            {
                val1 = rand.Next();
                val2 = rand.Next();
                bi1 = new BigInteger(val1);
                bi2 = new BigInteger(val2);

                Assert.AreEqual(BigInteger.GreatestCommonDivisor(val1, val2), bi1.gcd(bi2));
                Assert.AreEqual(bi1.gcd(bi2), bi2.gcd(bi1));
            }

            bi1 = new BigInteger();
            BigInteger.TryParse("23479237493274982374983729847392847928347982374983795749598459895479485945984598949799486346632864782376823768236482364862624623864", out bi1);

            Assert.AreEqual(bi1, bi1.gcd(0));
            Assert.AreEqual(1, bi1.gcd(1));
            Assert.AreEqual(1, bi1.gcd(-1));

            bi2 = new BigInteger();
            BigInteger.TryParse("3294823794872398749835984985798575794759834759347593475983475983475949530439", out bi2);

            Assert.AreEqual(1, bi2.gcd(bi1));

            bi2 = new BigInteger(2839392890293);
            Assert.AreEqual(1, bi1.gcd(bi2));

            bi1 = new BigInteger();
            BigInteger.TryParse("4951870740493721842141443925495861658429914087387823242795626852731793395869583123486587097315594003541474986183101777497261582259131154425", out bi1);
            bi2 = new BigInteger(25208378845650);
            Assert.AreEqual(12604189422825, bi2.gcd(bi1));
            Assert.AreEqual(bi1.gcd(bi2), bi2.gcd(bi1));

            bi2 = -bi2;
            Assert.AreEqual(12604189422825, bi2.gcd(bi1));
            Assert.AreEqual(bi1.gcd(bi2), bi2.gcd(bi1));

        }

        [TestMethod]
        public void TestModPow()
        {
            var a = new BigInteger();
            BigInteger.TryParse("4513022378190195207248111493619814210011122111521314021116172245292421892189133135249253284210917322371331631915863149241442281401995510735118116112172202199102116124234501111031274954151507124570516154178228146", out a);
            var n = new BigInteger();
            BigInteger.TryParse("2529589762471071921217177179249254145111191246515169611931940652006643560213582062372288573701152271112332092452431128143210751781625037196701031611573185126122233723864211061301331715378213129937", out n);


            var modulus = new BigInteger(1000000007);
            var res = a.modPow(n, modulus);
            Assert.AreEqual("868041175", res.ToString());

            modulus = new BigInteger();
            BigInteger.TryParse("922305412110716620326228851918622717821243928922818234109110014149250211422482", out modulus);
            res = a.modPow(n, modulus);
            BigInteger.TryParse("676144631297564803799040568236788209319025642240115630978591468748134664779002", out a);

            Assert.AreEqual(a, res);
        }

        [TestMethod]
        public void TestModInverse()
        {

            var a = new BigInteger();
            BigInteger.TryParse("470782681346529800216759025446747092045188631141622615445464429840250748896490263346676188477401449398784352124574498378830506322639352584202116605974693692194824763263949618703029846313252400361025245824301828641617858127932941468016666971398736792667282916657805322080902778987073711188483372360907612588995664533157503380846449774089269965646418521613225981431666593065726252482995754339317299670566915780168", out a);
            var b = a.modInverse(new BigInteger(1000000007));
            Assert.AreEqual("736445995", b.ToString());

            b = a.modInverse(new BigInteger(1999));
            Assert.AreEqual("1814", b.ToString());

            var isExceptionRaised = false;

        }

        [TestMethod]
        public void TestSecuredGenRandomBits()
        {
            { // Test < 32 bits
                var bi = new BigInteger();
                var rng = new RNGCryptoServiceProvider();
                var rand = new Random();

                bi = bi.genRandomBits(rand.Next(1, 33), rng);

                var bytes = bi.getBytes();
                var new_bytes = new byte[4];
                Array.Copy(bytes, new_bytes, bytes.Length);

                Assert.IsTrue(BitConverter.ToUInt32(new_bytes, 0) < (Math.Pow(2, 32) - 1));
            }

            // Test on random number of bits
            for (int i = 0; i < 9999; i++)
            {
                var bi = new BigInteger();
                var rng = new RNGCryptoServiceProvider();
                var rand = new Random();
                var bits = rand.Next(1, 70 * 32 + 1);
                bi = bi.genRandomBits(bits, rng);
                Assert.IsTrue(bits>= bi.bitCount());
                Assert.IsTrue(bi.Sign == 1|| bi.Sign == 0);
            }

            { // Test lower boudary value
                var bi = new BigInteger();
                var rng = new RNGCryptoServiceProvider();

                bi = bi.genRandomBits(1, rng);
                Assert.IsTrue(bi.getBytes()[0] == 1 || bi.getBytes()[0] == 0);
            }
        }

        [TestMethod]
        public void TestGenPseudoPrime()
        {
            // Test arbitrary values 
            for (int i = 0; i < 1; i++)
            {
                var bi = new BigInteger();
                var rng = new RNGCryptoServiceProvider();
                var rand = new Random();


                var coprime = bi.genPseudoPrime(rand.Next(1, 2241),5, rng);

                Assert.IsTrue(coprime.RabinMillerTest(5));
            }
        }

    }
}
