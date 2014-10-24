using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using ElGamalExt;

public class Test
{
    public static ElGamal encryptAlgorithm, decryptAlgorithm;
    public static int a, b, c;
    public static byte[] _a, _b, _c;


    public static void Main()
    {
        //TestTextEncryption();
        TestMultiplication();
        Console.ReadLine();
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

        a = rnd.Next(32768);
        b = rnd.Next(32768);

        ElGamal algorithm = new ElGamalManaged();
        algorithm.KeySize = 1024;
        algorithm.Padding = ElGamalPaddingMode.LeadingZeros;
        string parametersXML = algorithm.ToXmlString(true);
        Console.WriteLine("\n{0}\n", PrettifyXML(parametersXML));

        encryptAlgorithm = new ElGamalManaged();
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

        decryptAlgorithm = new ElGamalManaged();
        decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

        _a = encryptAlgorithm.EncryptData((new BigInteger(a)).getBytes());
        _b = encryptAlgorithm.EncryptData((new BigInteger(b)).getBytes());

        ProfileEncMul(25000);
        ProfilePlainMul(25000);
        
        var dec_a = new BigInteger(decryptAlgorithm.DecryptData(_a));
        var dec_b = new BigInteger(decryptAlgorithm.DecryptData(_b));
        var dec_c = new BigInteger(decryptAlgorithm.DecryptData(_c));

        Console.WriteLine("Encrypted: {0} * {1} = {2}", dec_a.ToString(), dec_b.ToString(), dec_c.ToString());
        Console.WriteLine("Plaintext: {0} * {1} = {2}", a.ToString(), b.ToString(), c.ToString());
        Console.WriteLine();
    }

    public static void ProfilePlainMul(int iterations)
    {
        // clean up
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        // warm up 
        c = a * b;

        var watch = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            c = a * b;
        }
        watch.Stop();

        Console.Write("Plaintext multiplication");
        Console.WriteLine(" Time Elapsed {0} ms", watch.Elapsed.TotalMilliseconds);
    } 

    public static void ProfileEncMul(int iterations)
    {
        // clean up
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        // warm up 
        _c = encryptAlgorithm.Multiply(_a, _b);

        var watch = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            _c = encryptAlgorithm.Multiply(_a, _b);
        }
        watch.Stop();

        Console.Write("ElGamal homomorphic multiplication");
        Console.WriteLine(" Time Elapsed {0} ms", watch.Elapsed.TotalMilliseconds);
    }
}