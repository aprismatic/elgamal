using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ElGamalExt;
using System.Text;

namespace ElGamalTests
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestTextEncryption()
        {
            int keySize;
            ElGamalPaddingMode padding = ElGamalPaddingMode.Zeros;
            string message = "Programming .NET Security";
            var plaintext = Encoding.Default.GetBytes(message);

            ElGamal algorithm = new ElGamalManaged();

            algorithm.Padding = padding;

            for (keySize = 384; keySize <= 544; keySize += 8)
            {
                algorithm.KeySize = keySize;

                string parametersXML = algorithm.ToXmlString(true);

                ElGamal encryptAlgorithm = new ElGamalManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                byte[] ciphertext = encryptAlgorithm.EncryptData(plaintext);

                ElGamal decryptAlgorithm = new ElGamalManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                byte[] candidatePlaintext = decryptAlgorithm.DecryptData(ciphertext);

                Assert.AreEqual(plaintext, candidatePlaintext);
            }
        }
    }
}
