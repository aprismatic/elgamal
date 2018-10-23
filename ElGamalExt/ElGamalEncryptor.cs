using BigIntegerExt;
using System;
using System.Numerics;
using System.Security.Cryptography;

namespace ElGamalExt
{
    public class ElGamalEncryptor : ElGamalAbstractCipher, IDisposable
    {
        private RandomNumberGenerator rng;

        public ElGamalEncryptor(ElGamalKeyStruct keyStruct)
            : base(keyStruct)
        {
            rng = RandomNumberGenerator.Create();
        }

        public byte[] ProcessBigInteger(BigInteger message)
        {
            if(BigInteger.Abs(message) > KeyStruct.MaxEncryptableValue)
                throw new ArgumentException($"Message to encrypt is too large. Message should be |m| < 2^{KeyStruct.getMaxPlaintextBits()-1}");

            // set random K
            BigInteger K;
            do
            {
                K = new BigInteger();
                K = K.GenRandomBits(KeyStruct.P.BitCount() - 1, rng);
            } while (BigInteger.GreatestCommonDivisor(K, KeyStruct.P - 1) != 1);

            var A = BigInteger.ModPow(KeyStruct.G, K, KeyStruct.P);
            var B = BigInteger.ModPow(KeyStruct.Y, K, KeyStruct.P) * Encode(message) % KeyStruct.P;

            var a_bytes = A.ToByteArray();
            var b_bytes = B.ToByteArray();

            // create an array to contain the ciphertext
            var res = new byte[CiphertextBlocksize];

            Array.Copy(a_bytes, 0, res, 0, a_bytes.Length);
            Array.Copy(b_bytes, 0, res, res.Length / 2, b_bytes.Length);

            return res;
        }

        private BigInteger Encode(BigInteger origin)
        {
            if (origin < 0)
                return KeyStruct.MaxRawPlaintext + origin + 1;
            return origin;
        }

        public void Dispose()
        {
            rng.Dispose();
        }
    }
}
