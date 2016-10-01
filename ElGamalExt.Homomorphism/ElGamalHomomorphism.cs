using System;



namespace ElGamalExt.Homomorphism
{
    public static class ElGamalHomomorphism
    {
        public static byte[] Multiply(byte[] p_first, byte[] p_second, byte[] p_P)
        {
            var blocksize = p_first.Length;

            var res = new byte[blocksize];

            var P = new BigInteger(p_P);
            var A_left = new BigInteger(p_first, blocksize / 2);
            var A_right = new BigInteger(p_first, blocksize / 2, blocksize / 2);
            var B_left = new BigInteger(p_second, blocksize / 2);
            var B_right = new BigInteger(p_second, blocksize / 2, blocksize / 2);
            
            var res_left = (A_left * B_left) % P;
            var res_right = (A_right * B_right) % P;

            var cAbytes = res_left.getBytes();
            var cBbytes = res_right.getBytes();

            Array.Copy(cAbytes, 0, res, blocksize / 2 - cAbytes.Length, cAbytes.Length);
            Array.Copy(cBbytes, 0, res, blocksize - cBbytes.Length, cBbytes.Length);

            return res;
        }
    }
}
