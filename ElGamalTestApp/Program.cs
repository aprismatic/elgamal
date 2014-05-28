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
        multiply();
        return;

        // define the byte array that we will use
        // as plaintext
        byte[] plaintext
            = Encoding.Default.GetBytes("Programming .NET Security");

        // Create an instance of the algorithm and generate some keys
        ElGamal algorithm = new ElGamalManaged();
        // set the key size - keep it small to speed up the tests
        algorithm.KeySize = 384;
        // extract and print the xml string (this will cause
        // a new key pair to be generated)
        string parametersXML = algorithm.ToXmlString(true);
        Console.WriteLine("\n{0}\n", PrettifyXML(parametersXML));

        // Test the basic encryption support
        ElGamal encryptAlgorithm = new ElGamalManaged();
        // set the keys - note that we export without the
        // private parameters since we are encrypting data
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));
        byte[] ciphertext = encryptAlgorithm.EncryptData(plaintext);

        // create a new instance of the algorithm to decrypt
        ElGamal decryptAlgorithm = new ElGamalManaged();
        // set the keys - note that we export with the
        // private parameters since we are decrypting data
        decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));
        // restore the plaintext
        byte[] candidatePlaintext = decryptAlgorithm.DecryptData(ciphertext);

        Console.WriteLine("BASIC ENCRYPTION: {0}",
            CompareArrays(plaintext, candidatePlaintext));
    }

    private static bool CompareArrays(byte[] p_arr1, byte[] p_arr2)
    {
        for (int i = 0; i < p_arr1.Length; i++)
        {
            if (p_arr1[i] != p_arr2[i])
            {
                return false;
            }
        }
        return true;
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

    public static void multiply()
    {
        var a = new BigInteger(20);
        var b = new BigInteger(2);

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
        var c = new BigInteger(decryptAlgorithm.DecryptData(c_bytes));
            a = new BigInteger(decryptAlgorithm.DecryptData(a_bytes));
            b = new BigInteger(decryptAlgorithm.DecryptData(b_bytes)); 
                
        Console.WriteLine("{0} * {1} = {2}", a.ToString(), b.ToString(), c.ToString());
    }
}