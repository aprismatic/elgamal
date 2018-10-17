using System;
using System.Numerics;

namespace ElGamalExt
{
    public struct BigFraction
    {
        //Paramaters Numerator / Denominator
        public BigInteger Numerator;
        public BigInteger Denominator;

        //CONSTRUCTORS

        //Fractional number constructor
        public BigFraction(BigInteger num, BigInteger den)
        {
            BigInteger gcd = BigInteger.GreatestCommonDivisor(num, den);
            Numerator = num / gcd;
            Denominator = den / gcd;
        }
        public BigFraction(BigInteger num)
        {
            Numerator = num;
            Denominator = BigInteger.One;
        }

        //Decimal constructor
        public BigFraction(decimal dec)
        {
            int count = BitConverter.GetBytes(decimal.GetBits(dec)[3])[2];  //count decimal places
            Numerator = new BigInteger(dec * (Decimal)Math.Pow(10, count));
            Denominator = new BigInteger(Math.Pow(10, count));
            Simplify();
        }

        //Double constructor
        public BigFraction(double dou)
        {
            string str = dou.ToString();
            int exponment = str.Length - str.IndexOf(".") - 1;
            Numerator = new BigInteger(Math.Pow(10, exponment) * dou);
            Denominator = new BigInteger(Math.Pow(10, exponment));
            Simplify();
        }

        //Int constructor
        public BigFraction(long integer)
        {
            Numerator = new BigInteger(integer);
            Denominator = BigInteger.One;
            Simplify();
        }

        //CONVERSIONS

        //User-defined conversion from BigInteger to BigFraction
        public static implicit operator BigFraction(BigInteger bigint)
        {
            return new BigFraction(bigint);
        }

        //User-defined conversion from Decimal to BigFraction
        public static implicit operator BigFraction(decimal dec)
        {
            return new BigFraction(dec);
        }

        //User-defined conversion from Double to BigFraction
        public static implicit operator BigFraction(double dou)
        {
            return new BigFraction(dou);
        }

        //User-defined conversion from Int to BigFraction
        public static implicit operator BigFraction(long integer)
        {
            return new BigFraction(integer);
        }

        //OPERATORS

        //Operator %
        public static BigFraction operator %(BigFraction r, BigInteger mod)
        {
            BigInteger modmulden = r.Denominator * mod;
            BigInteger remainder = r.Numerator % modmulden;
            BigFraction answer = new BigFraction(remainder, r.Denominator);
            answer.Simplify();
            return answer;
        }

        //Operator >
        public static Boolean operator >(BigFraction r1, BigFraction r2)
        {
            BigInteger r1compare = r1.Numerator * r2.Denominator;
            BigInteger r2compare = r2.Numerator * r1.Denominator;
            if (r1compare.CompareTo(r2compare) == 1) { return true; }
            else { return false; }
        }

        //Operator <
        public static Boolean operator <(BigFraction r1, BigFraction r2)
        {
            BigInteger r1compare = r1.Numerator * r2.Denominator;
            BigInteger r2compare = r2.Numerator * r1.Denominator;
            if (r1compare.CompareTo(r2compare) == -1) { return true; }
            else { return false; }
        }

        //Operator ==
        public static Boolean operator ==(BigFraction r1, BigFraction r2)
        {
            BigInteger r1compare = r1.Numerator * r2.Denominator;
            BigInteger r2compare = r2.Numerator * r1.Denominator;
            if (r1compare.CompareTo(r2compare) == 0) { return true; }
            else { return false; }
        }

        //Operator !=
        public static Boolean operator !=(BigFraction r1, BigFraction r2)
        {
            BigInteger r1compare = r1.Numerator * r2.Denominator;
            BigInteger r2compare = r2.Numerator * r1.Denominator;
            if (r1compare.CompareTo(r2compare) == 0) { return false; }
            else { return true; }
        }

        //Operator -
        public static BigFraction operator -(BigFraction a, BigFraction b)
        {
            a.Numerator = a.Numerator * b.Denominator - b.Numerator * a.Denominator;
            a.Denominator = a.Denominator * b.Denominator;
            a.Simplify();
            return a;
        }

        //Operator +
        public static BigFraction operator +(BigFraction a, BigFraction b)
        {
            a.Numerator = a.Numerator * b.Denominator + b.Numerator * a.Denominator;
            a.Denominator = a.Denominator * b.Denominator;
            a.Simplify();
            return a;
        }

        //Operator *
        public static BigFraction operator *(BigFraction a, BigFraction b)
        {
            a.Numerator = a.Numerator * b.Numerator;
            a.Denominator = a.Denominator * b.Denominator;
            a.Simplify();
            return a;
        }

        //Operator /
        public static BigFraction operator /(BigFraction a, BigFraction b)
        {
            a.Numerator = a.Numerator * b.Denominator;
            a.Denominator = a.Denominator * b.Numerator;
            a.Simplify();
            return a;
        }

        //Override Equals
        public override bool Equals(object obj)
        {
            if (obj == null) { return false; }

            BigFraction comparebigfrac = (BigFraction)obj;
            return (Numerator == comparebigfrac.Numerator) && (Denominator == comparebigfrac.Denominator);
        }

        //Override GetHashCode
        public override int GetHashCode()
        {
            return Numerator.GetHashCode() ^ Denominator.GetHashCode();
        }

        //Override ToString
        public override string ToString()
        {
            return Numerator.ToString() + "/" + Denominator.ToString();
        }

        //MISC

        public void Simplify()
        {
            BigInteger gcd = BigInteger.GreatestCommonDivisor(Numerator, Denominator);
            Numerator = Numerator / gcd;
            Denominator = Denominator / gcd;
        }
    }
}
