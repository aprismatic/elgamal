using ElGamalExt;

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;

public class Test
{
    public static void Main()
    {
        TestTextEncryption();
        //TestMultiplication_Batch();
        //PerformanceTest();
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

    public static void TestMultiplication_Batch()
    {
        Console.WriteLine();
        Console.WriteLine("-- Testing multiplication in batch ------");

        var rnd = new Random();

        for (int i = 0; i < 3; i++)
        // testing for 3 sets of key
        {
            Console.WriteLine("- Testing for key No.{0} -", i);
            ElGamal algorithm = new ElGamalManaged();
            algorithm.KeySize = 384;
            algorithm.Padding = ElGamalPaddingMode.LeadingZeros;
            string parametersXML = algorithm.ToXmlString(true);

            ElGamal encryptAlgorithm = new ElGamalManaged();
            encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

            ElGamal decryptAlgorithm = new ElGamalManaged();
            decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

            int error_counter = 0;
            for (int j = 0; j < 50; j++)
            // testing for 50 pairs of random numbers
            {
                var a = new BigInteger(rnd.Next());
                var b = new BigInteger(rnd.Next());

                var a_bytes = encryptAlgorithm.EncryptData(a.getBytes());
                var b_bytes = encryptAlgorithm.EncryptData(b.getBytes());

                var c_bytes = encryptAlgorithm.Multiply(a_bytes, b_bytes);

                var dec_c = new BigInteger(decryptAlgorithm.DecryptData(c_bytes));
                var dec_a = new BigInteger(decryptAlgorithm.DecryptData(a_bytes));
                var dec_b = new BigInteger(decryptAlgorithm.DecryptData(b_bytes));

                var ab_result = a * b;
                if (dec_c != ab_result)
                {
                    error_counter++;
                    Console.WriteLine("Failure #{0}", error_counter);
                    Console.WriteLine("Key = {0}", PrettifyXML(parametersXML));
                    Console.WriteLine("Encrypted: {0} * {1} = {2}", dec_a.ToString(), dec_b.ToString(), dec_c.ToString());
                    Console.WriteLine("Plaintext: {0} * {1} = {2}", a.ToString(), b.ToString(), ab_result.ToString());
                    Console.WriteLine();
                }
            }
            Console.WriteLine("There are {0}/50 cases that do not pass the test", error_counter);
            Console.WriteLine();
        }
    }

    public static void PerformanceTest()
    {
        Console.WriteLine();
        Console.WriteLine("-- Performance Test --");

        long total_time_plaintext = 0;
        long total_time_encrypted = 0;

        for (int i = 0; i < 10; i++)
        {
            Console.WriteLine("-- Performance test iteration {0} --", i);

            total_time_plaintext += ProfilePlaintextMUL(250000);
            total_time_encrypted += ProfileEncryptedMUL(250000);
        }

        Console.WriteLine("Total time for plaintext multiplication  = {0} ticks", total_time_plaintext);
        Console.WriteLine("Total time for ciphertext multiplication = {0} ticks", total_time_encrypted);
        Console.WriteLine();
    }

    private static long ProfilePlaintextMUL(int iterations)
    {
        // clean up
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var rnd = new Random();

        // prepare and warm up 
        var a = rnd.Next(32768);
        var b = rnd.Next(32768);
        var c = a * b;

        var watch = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            c = a * b;
        }
        watch.Stop();

        return watch.Elapsed.Ticks;
    }

    private static long ProfileEncryptedMUL(int iterations)
    {
        // clean up
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var rnd = new Random();

        // prepare and warm up 
        ElGamal algorithm = new ElGamalManaged();
        algorithm.KeySize = 384;
        algorithm.Padding = ElGamalPaddingMode.LeadingZeros;
        string parametersXML = algorithm.ToXmlString(true);

        ElGamal encryptAlgorithm = new ElGamalManaged();
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

        var a = new BigInteger(rnd.Next(32768));
        var a_bytes = encryptAlgorithm.EncryptData(a.getBytes());

        var b = new BigInteger(rnd.Next(32768));
        var b_bytes = encryptAlgorithm.EncryptData(b.getBytes());

        var c_bytes = encryptAlgorithm.Multiply(a_bytes, b_bytes);

        var watch = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            c_bytes = encryptAlgorithm.Multiply(a_bytes, b_bytes);
        }
        watch.Stop();

        return watch.Elapsed.Ticks;
    }
}