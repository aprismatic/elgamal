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
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using System.Numerics;
using BigIntegerExt;
using Numerics;

namespace ElGamalExt
{
    public class ElGamal : AsymmetricAlgorithm
    {
		private ElGamalKeyStruct o_key_struct;
		private static readonly BigInteger max = BigInteger.Pow(2, 256) - BigInteger.One;

		public ElGamalKeyStruct KeyStruct
		{
			get
			{
				if (NeedToGenerateKey())
				{
					CreateKeyPair(KeySizeValue);
				}
				return o_key_struct;
			}
			set
			{
				o_key_struct = value;
			}
		}

		public ElGamal()
		{
			// create the key struct and set all of the big integers to zero
			o_key_struct = new ElGamalKeyStruct
			{
				P = BigInteger.Zero,
				G = BigInteger.Zero,
				Y = BigInteger.Zero,
				X = BigInteger.Zero
			};

			// set the default key size value
			KeySizeValue = 384;

			// set the default padding mode
			//Padding = ElGamalPaddingMode.BigIntegerPadding;

			// set the range of legal keys
			LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };
		}

		private bool NeedToGenerateKey()
		{
			return (o_key_struct.P == 0) && (o_key_struct.G == 0) && (o_key_struct.Y == 0);
		}

		private void CreateKeyPair(int p_key_strength)
		{
			using (var x_random_generator = RandomNumberGenerator.Create())
			{
				// create the large prime number, P
				o_key_struct.P = o_key_struct.P.GenPseudoPrime(p_key_strength, 16, x_random_generator);

				// create the two random numbers, which are smaller than P
				o_key_struct.X = new BigInteger();
				o_key_struct.X = o_key_struct.X.GenRandomBits(p_key_strength - 1, x_random_generator);
				o_key_struct.G = new BigInteger();
				o_key_struct.G = o_key_struct.G.GenRandomBits(p_key_strength - 1, x_random_generator);

				// compute Y
				o_key_struct.Y = BigInteger.ModPow(o_key_struct.G, o_key_struct.X, o_key_struct.P);

				//o_key_struct.Padding = Padding;
			}
		}

		public byte[][] EncryptData(BigRational p_data)
		{
			if (NeedToGenerateKey())
			{
				CreateKeyPair(KeySizeValue);
			}

			using (var x_enc = new ElGamalEncryptor(o_key_struct))
			{
				var numerator = x_enc.ProcessBigInteger(p_data.Numerator);
				var denominator = x_enc.ProcessBigInteger(p_data.Denominator);
				var array = new byte[][] { numerator, denominator };
				return array;
			}
		}

		public BigRational DecryptData(byte[][] p_data)
		{
			if (NeedToGenerateKey())
			{
				CreateKeyPair(KeySizeValue);
			}

			var x_enc = new ElGamalDecryptor(o_key_struct);

			var numerator = x_enc.ProcessByteBlock(p_data[0]);
			var denominator = x_enc.ProcessByteBlock(p_data[1]);
			var floating = new BigRational(numerator, denominator);

			return floating;
		}

		public byte[][] Multiply(byte[][] p_first, byte[][] p_second)
		{
			var mul_numerator =  Homomorphism.ElGamalHomomorphism.Multiply(p_first[0], p_second[0], o_key_struct.P.ToByteArray());
			var mul_denominator = Homomorphism.ElGamalHomomorphism.Multiply(p_first[1], p_second[1], o_key_struct.P.ToByteArray());
			var mul = new byte[][] { mul_numerator, mul_denominator };
			return mul;
		}

		public byte[][] Divide(byte[][] p_first, byte[][] p_second)
		{
			var mul_numerator = Homomorphism.ElGamalHomomorphism.Multiply(p_first[0], p_second[1], o_key_struct.P.ToByteArray());
			var mul_denominator = Homomorphism.ElGamalHomomorphism.Multiply(p_first[1], p_second[0], o_key_struct.P.ToByteArray());
			var mul = new byte[][] { mul_numerator, mul_denominator };
			return mul;
		}

		public void ImportParameters(ElGamalParameters p_parameters)
		{
			// obtain the  big integer values from the byte parameter values
			o_key_struct.P = new BigInteger(p_parameters.P);
			o_key_struct.G = new BigInteger(p_parameters.G);
			o_key_struct.Y = new BigInteger(p_parameters.Y);
			//o_key_struct.Padding = p_parameters.Padding;

			if (p_parameters.X != null && p_parameters.X.Length > 0)
			{
				o_key_struct.X = new BigInteger(p_parameters.X);
			}

			// set the length of the key based on the import
			KeySizeValue = o_key_struct.P.BitCount();
			//Padding = o_key_struct.Padding;
		}

		public ElGamalParameters ExportParameters(bool p_include_private_params)
		{
			if (NeedToGenerateKey())
			{
				CreateKeyPair(KeySizeValue);
			}

			// create the parameter set and set the public values of the parameters
			var x_params = new ElGamalParameters
			{
				P = o_key_struct.P.ToByteArray(),
				G = o_key_struct.G.ToByteArray(),
				Y = o_key_struct.Y.ToByteArray(),
				//Padding = o_key_struct.Padding
			};

			// if required, include the private value, X
			if (p_include_private_params)
			{
				x_params.X = o_key_struct.X.ToByteArray();
			}
			else
			{
				// ensure that we zero the value
				x_params.X = new byte[1];
			}

			return x_params;
		}

		public override string ToXmlString(bool p_include_private)
        {
            var x_params = ExportParameters(p_include_private);

            var x_sb = new StringBuilder();

            x_sb.Append("<ElGamalKeyValue>");

            x_sb.Append("<P>" + Convert.ToBase64String(x_params.P) + "</P>");
            x_sb.Append("<G>" + Convert.ToBase64String(x_params.G) + "</G>");
            x_sb.Append("<Y>" + Convert.ToBase64String(x_params.Y) + "</Y>");
            //x_sb.Append("<Padding>" + x_params.Padding.ToString() + "</Padding>");

            if (p_include_private)
            {
                // we need to include X, which is the part of private key
                x_sb.Append("<X>" + Convert.ToBase64String(x_params.X) + "</X>");
            }

            x_sb.Append("</ElGamalKeyValue>");

            return x_sb.ToString();
        }

        public override void FromXmlString(string p_string)
        {
            var x_params = new ElGamalParameters();

            var keyValues = XDocument.Parse(p_string).Element("ElGamalKeyValue");

            x_params.P = Convert.FromBase64String((String)keyValues.Element("P") ?? "");
            x_params.G = Convert.FromBase64String((String)keyValues.Element("G") ?? "");
            x_params.Y = Convert.FromBase64String((String)keyValues.Element("Y") ?? "");
            //x_params.Padding = (ElGamalPaddingMode)Enum.Parse(typeof(ElGamalPaddingMode), (String)keyValues.Element("Padding") ?? "");
            x_params.X = Convert.FromBase64String((String)keyValues.Element("X") ?? "");

            ImportParameters(x_params);
        }
    }
}
