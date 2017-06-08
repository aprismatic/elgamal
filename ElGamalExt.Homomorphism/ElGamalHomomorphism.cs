using System;
using System.Numerics;
using ElGamalExt.BigInt;

namespace ElGamalExt.Homomorphism
{
    public static class ElGamalHomomorphism
    {
        public static byte[] Multiply(byte[] p_first, byte[] p_second, byte[] p_P)
        {
            var blocksize = p_first.Length;

            var res = new byte[blocksize];

            var P = new BigInteger(p_P);
            var temp = new byte[blocksize / 2];
            Array.Copy(p_first, temp, blocksize / 2);
            var A_left = new BigInteger(temp);
            Array.Copy(p_first, blocksize / 2, temp, 0, blocksize / 2);
            var A_right = new BigInteger(temp);
            Array.Copy(p_second, temp, blocksize / 2);
            var B_left = new BigInteger(temp);
            Array.Copy(p_second, blocksize / 2, temp, 0, blocksize / 2);
            var B_right = new BigInteger(temp);
            
            var res_left = (A_left * B_left) % P;
            var res_right = (A_right * B_right) % P;

            var cAbytes = res_left.ToByteArray();
            var cBbytes = res_right.ToByteArray();

            Array.Copy(cAbytes, 0, res, 0, cAbytes.Length);
            Array.Copy(cBbytes, 0, res, blocksize / 2, cBbytes.Length);

            return res;
        }
    }
}
