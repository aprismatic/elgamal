using System;
using System.IO;
using System.Xml;
using System.Text;
using System.Security.Cryptography;
using ElGamalExt;
using System.Linq;

public class Test
{

    public static void Main()
    {
        TestTextEncryption();
        TestMultiplication();
        return;
    }    

    public static String PrettifyXML(String XML)
    {
        String Result = "";

        MemoryStream mStream = new MemoryStream();
        XmlTextWriter writer = new XmlTextWriter(mStream, Encoding.Unicode);
        XmlDocument document = new XmlDocument();

        try
        {
            // Load the XmlDocument with the XML.
            document.LoadXml(XML);

            writer.Formatting = Formatting.Indented;

            // Write the XML into a formatting XmlTextWriter
            document.WriteContentTo(writer);
            writer.Flush();
            mStream.Flush();

            // Have to rewind the MemoryStream in order to read
            // its contents.
            mStream.Position = 0;

            // Read MemoryStream contents into a StreamReader.
            StreamReader sReader = new StreamReader(mStream);

            // Extract the text from the StreamReader.
            String FormattedXML = sReader.ReadToEnd();

            Result = FormattedXML;
        }
        catch (XmlException)
        {
        }

        mStream.Close();
        writer.Close();

        return Result;
    }

    public static void TestTextEncryption(string message = "Programming .NET Security", int keySize = 384, ElGamalPaddingMode padding = ElGamalPaddingMode.Zeros)
    {
        Console.WriteLine();
        Console.WriteLine("-- Testing string encryption ---");

        byte[] plaintext = Encoding.Default.GetBytes(message);

        ElGamal algorithm = new ElGamalManaged();

        algorithm.KeySize = keySize;
        algorithm.Padding = padding;

        string parametersXML = algorithm.ToXmlString(true);
        Console.WriteLine("\n{0}\n", PrettifyXML(parametersXML));

        ElGamal encryptAlgorithm = new ElGamalManaged();
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

        byte[] ciphertext = encryptAlgorithm.EncryptData(plaintext);

        ElGamal decryptAlgorithm = new ElGamalManaged();
        decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

        byte[] candidatePlaintext = decryptAlgorithm.DecryptData(ciphertext);

        Console.WriteLine("Original string:  '{0}'", message);
        Console.WriteLine("Decrypted string: '{0}'", Encoding.Default.GetString(candidatePlaintext));
        Console.WriteLine("Byte arrays equal: {0}", plaintext.SequenceEqual(candidatePlaintext));
        Console.WriteLine();
    }

    public static void TestMultiplication()
    {
        Console.WriteLine();
        Console.WriteLine("-- Testing multiplication ------");

        var rnd = new Random();

        var a = new BigInteger(rnd.Next());
        var b = new BigInteger(rnd.Next());

        ElGamal algorithm = new ElGamalManaged();
        algorithm.KeySize = 384;
        algorithm.Padding = ElGamalPaddingMode.LeadingZeros;
        string parametersXML = algorithm.ToXmlString(true);
        Console.WriteLine("\n{0}\n", PrettifyXML(parametersXML));

        ElGamal encryptAlgorithm = new ElGamalManaged();
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

        var a_bytes = encryptAlgorithm.EncryptData(a.getBytes());
        var b_bytes = encryptAlgorithm.EncryptData(b.getBytes());

        var c_bytes = encryptAlgorithm.Multiply(a_bytes, b_bytes);

        ElGamal decryptAlgorithm = new ElGamalManaged();
        decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));
        var dec_c = new BigInteger(decryptAlgorithm.DecryptData(c_bytes));
        var dec_a = new BigInteger(decryptAlgorithm.DecryptData(a_bytes));
        var dec_b = new BigInteger(decryptAlgorithm.DecryptData(b_bytes));

        Console.WriteLine("Encrypted: {0} * {1} = {2}", dec_a.ToString(), dec_b.ToString(), dec_c.ToString());
        Console.WriteLine("Plaintext: {0} * {1} = {2}", a.ToString(), b.ToString(), (a * b).ToString());
        Console.WriteLine();
    }
}