/************************************************************************************
 This implementation of the ElGamal encryption scheme is based on the code from [1].
 
 This library is provided as-is and is covered by the MIT License [2] (except for the
 parts that belong to O'Reilly - they are covered by [3]).
  
 [1] Adam Freeman & Allen Jones, Programming .NET Security: O'Reilly Media, 2003,
     ISBN 9780596552275 (http://books.google.com.sg/books?id=ykXCNVOIEuQC)
 
 [2] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)
 
 [3] Tim O'Reilly, O'Reilly Policy on Re-Use of Code Examples from Books: website,
     2001, (http://www.oreillynet.com/pub/a/oreilly/ask_tim/2001/codepolicy.html)
 ************************************************************************************/

using System;
using System.Numerics;
using System.Security.Cryptography;

namespace ElGamalExt.BigInt
{
    public static class ElGamalBigIntegerFunctions
    {
        // primes smaller than 2000 to test the generated prime number
        public static readonly int[] primesBelow2000 = {
           2,    3,    5,    7,   11,   13,   17,   19,   23,   29,   31,   37,   41,   43,   47,   53,   59,   61,   67,   71,
          73,   79,   83,   89,   97,  101,  103,  107,  109,  113,  127,  131,  137,  139,  149,  151,  157,  163,  167,  173,
         179,  181,  191,  193,  197,  199,  211,  223,  227,  229,  233,  239,  241,  251,  257,  263,  269,  271,  277,  281,
         283,  293,  307,  311,  313,  317,  331,  337,  347,  349,  353,  359,  367,  373,  379,  383,  389,  397,  401,  409,
         419,  421,  431,  433,  439,  443,  449,  457,  461,  463,  467,  479,  487,  491,  499,  503,  509,  521,  523,  541,
         547,  557,  563,  569,  571,  577,  587,  593,  599,  601,  607,  613,  617,  619,  631,  641,  643,  647,  653,  659,
         661,  673,  677,  683,  691,  701,  709,  719,  727,  733,  739,  743,  751,  757,  761,  769,  773,  787,  797,  809,
         811,  821,  823,  827,  829,  839,  853,  857,  859,  863,  877,  881,  883,  887,  907,  911,  919,  929,  937,  941,
         947,  953,  967,  971,  977,  983,  991,  997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
        1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223,
        1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373,
        1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
        1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657,
        1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811,
        1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987,
        1993, 1997, 1999 };

        /// <summary>
        /// Modulo Exponentiation
        /// </summary>
        /// <param name="exp">Exponential</param>
        /// <param name="n">Modulo</param>
        /// <returns>BigInteger result of raising this to the power of exp and then modulo n </returns>
        public static BigInteger modPow(this BigInteger T, BigInteger exp, BigInteger mod)
        {
            return BigInteger.ModPow(T, exp, mod);
        }


        /// <summary>
        /// Returns the modulo inverse of this
        /// </summary>
        /// <remarks>
        /// Throws ArithmeticException if the inverse does not exist.  (i.e. gcd(this, modulus) != 1)
        /// </remarks>
        /// <param name="modulus"></param>
        /// <returns>Modulo inverse of this</returns>
        public static BigInteger modInverse(this BigInteger T,  BigInteger mod)
        {
            return BigInteger.ModPow(T, mod-2, mod);
        }


        /// <summary>
        /// Returns gcd(this, bi)
        /// </summary>
        /// <param name="bi"></param>
        /// <returns>Greatest Common Divisor of this and bi</returns>
        public static BigInteger gcd(this BigInteger T, BigInteger bi)
        {
            return BigInteger.GreatestCommonDivisor(T, bi);
        }


        /// <summary>
        /// Returns the value of the BigInteger as a byte array
        /// </summary>
        /// <remarks>
        /// The lowest index contains the MSB
        /// </remarks>
        /// <returns>Byte array containing value of the BigInteger</returns>
        public static byte[] getBytes(this BigInteger T)
        {
            byte[] source = T.ToByteArray();
            byte[] result = new byte[source.Length-1];

            if (source[source.Length - 1] == 0)
            {
                Array.Copy(source, result, source.Length - 1);
                return result;
            }

            return source;
        }


        /// <summary>
        /// Returns the position of the most significant bit in the BigInteger
        /// </summary>
        /// <example>
        /// 1) The result is 1, if the value of BigInteger is 0...0000 0000
        /// 2) The result is 1, if the value of BigInteger is 0...0000 0001
        /// 3) The result is 2, if the value of BigInteger is 0...0000 0010
        /// 4) The result is 2, if the value of BigInteger is 0...0000 0011
        /// 5) The result is 5, if the value of BigInteger is 0...0001 0011
        /// </example>
        /// <returns></returns>
        public static int bitCount(this BigInteger T)
        {
            int bitLength = 0;
            while (T / 2 != 0)
            {
                T /= 2;
                bitLength++;
            }
            bitLength += 1;
            return bitLength;
        }


        /// <summary>
        /// Returns length in bytes
        /// </summary>
        /// <returns>Length in bytes</returns>
        public static int dataLength(this BigInteger T)
        {
            return T.getBytes().Length;
        }


        /// <summary>
        /// Populates "this" with the specified amount of random bits (secured version)
        /// </summary>
        /// <param name="bits"></param>
        /// <param name="rng"></param>
        public static BigInteger genRandomBits(this BigInteger T, int bits, RNGCryptoServiceProvider rng)
        {

            byte[] randBytes = new byte[(bits / 8) + 1];
            BigInteger R;
            double remainderSum = 0;

            rng.GetBytes(randBytes);

            if (bits % 8 != 0)
            {
                randBytes[randBytes.Length - 1] &= (byte)0x7F; //force sign bit to positive  
                for (int i = 0; i < bits % 8; i++)
                {
                    remainderSum += Math.Pow(2, i);
                }
                randBytes[randBytes.Length - 1] &= (byte)Convert.ToUInt16(remainderSum);
                randBytes[randBytes.Length - 1] |= (byte)Convert.ToUInt16(Math.Pow(2, (bits % 8 - 1)));

            }
            else
            {
                randBytes[randBytes.Length - 1] &= (byte)0x00; //force sign bit to positive
                randBytes[randBytes.Length - 2] |= (byte)0x80;
            }


            R = new BigInteger(randBytes);
            int a = R.bitCount();

            return R;

        }


        /// <summary>
        /// Generates a positive BigInteger that is probably prime (secured version)
        /// </summary>
        /// <param name="bits">Number of bit</param>
        /// <param name="confidence">Number of chosen bases</param>
        /// <param name="rand">RNGCryptoServiceProvider object</param>
        /// <returns>A probably prime number</returns>
        public static BigInteger genPseudoPrime(this BigInteger T, int bits, int confidence, RNGCryptoServiceProvider rand)
        {
            BigInteger result = new BigInteger();
            bool done = false;

            while (!done)
            {
                result = result.genRandomBits(bits, rand);
                result = result.IsEven ? result += 1 : result;

                // prime test
                done = result.isProbablePrime(confidence);
            }

            return result;

        }


        /// <summary>
        /// Determines whether a number is probably prime using the Rabin-Miller's test
        /// </summary>
        /// <remarks>
        /// Before applying the test, the number is tested for divisibility by primes &lt; 2000
        /// </remarks>
        /// <param name="confidence">Number of chosen bases</param>
        /// <returns>True if this is probably prime</returns>
        public static bool isProbablePrime(this BigInteger T, int confidence)
        {
            byte[] data = T.ToByteArray();
            BigInteger thisVal;
            if ((data[data.Length-1] & 0x8) != 0)        // negative
                thisVal = -1* T;
            else
                thisVal = T;

            // test for divisibility by primes < 2000
            for (int p = 0; p < primesBelow2000.Length; p++)
            {
                BigInteger divisor = primesBelow2000[p];

                if (divisor >= thisVal)
                    break;

                BigInteger resultNum = BigInteger.Remainder(thisVal, divisor);
                if (resultNum == BigInteger.Zero)
                    return false;
            }

            if (thisVal.RabinMillerTest(confidence))
                return true;
            else
                return false;
        }


        /// <summary>
        /// Probabilistic prime test based on Rabin-Miller's
        /// </summary>
        /// <remarks>
        /// for any p &gt; 0 with p - 1 = 2^s * t
        ///
        /// p is probably prime (strong pseudoprime) if for any a &lt; p,
        /// 1) a^t mod p = 1 or
        /// 2) a^((2^j)*t) mod p = p-1 for some 0 &lt;= j &lt;= s-1
        ///
        /// Otherwise, p is composite.
        /// </remarks>
        /// <param name="confidence">Number of chosen bases</param>
        /// <returns>True if this is a strong pseudoprime to randomly chosen bases</returns>
        public static bool RabinMillerTest(this BigInteger T, int confidence)
        {
            if (T == 2 || T == 3)
                return true;
            if (T < 2 || T % 2 == 0)
                return false;

            BigInteger d = T - 1;
            int s = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                s += 1;
            }

            // There is no built-in method for generating random BigInteger values.
            // Instead, random BigIntegers are constructed from randomly generated
            // byte arrays of the same length as the T.
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            byte[] bytes = new byte[T.ToByteArray().LongLength];
            BigInteger a;

            for (int i = 0; i < confidence; i++)
            {
                do
                {
                    rng.GetBytes(bytes);
                    a = new BigInteger(bytes);
                }
                while (a < 2 || a >= T - 2);

                BigInteger x = BigInteger.ModPow(a, d, T);
                if (x == 1 || x == T - 1)
                    continue;

                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, T);
                    if (x == 1)
                        return false;
                    if (x == T - 1)
                        break;
                }

                if (x != T - 1)
                    return false;
            }

            return true;
        }
    }
}
