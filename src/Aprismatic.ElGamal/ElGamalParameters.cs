using System;
using System.Numerics;
using System.Text;
using System.Xml.Linq;

namespace Aprismatic.ElGamal
{
    [Serializable]
    public struct ElGamalParameters
    {
        // public portion
        public byte[] P;
        public byte[] G;
        public byte[] Y;
        public int MaxPlaintextBits;

        // private portion
        public byte[] X;

        public static ElGamalParameters FromXml(string Xml)
        {
            var res = new ElGamalParameters();
            
            var kv = XDocument.Parse(Xml).Element("ElGamalKeyValue");

            // PARSE THE PUBLIC KEY PORTION
            var kvelP = kv.Element("P");
            if(kvelP == null)
                throw new ArgumentException("Provided XML does not have a public key value `P`");
            res.P = Convert.FromBase64String(kvelP.Value);

            var kvelG = kv.Element("G");
            if (kvelG == null)
                throw new ArgumentException("Provided XML does not have a public key value `G`");
            res.G = Convert.FromBase64String(kvelG.Value);

            var kvelY = kv.Element("Y");
            if (kvelY == null)
                throw new ArgumentException("Provided XML does not have a public key value `Y`");
            res.Y = Convert.FromBase64String(kvelY.Value);

            var kvelMPB = kv.Element("MaxPlaintextBits");
            res.MaxPlaintextBits = kvelMPB != null ? int.Parse(kvelMPB.Value) : ElGamalKeyDefaults.DefaultMaxPlaintextBits;

            // PARSE THE PRIVATE KEY PORTION
            var kvelX = kv.Element("X");
            res.X = kvelX == null ? BigInteger.Zero.ToByteArray() : Convert.FromBase64String(kvelX.Value);

            return res;
        }

        public string ToXml(bool includePrivateParameters)
        {
            var sb = new StringBuilder();

            sb.Append("<ElGamalKeyValue>");

            sb.Append("<P>" + Convert.ToBase64String(P) + "</P>");
            sb.Append("<G>" + Convert.ToBase64String(G) + "</G>");
            sb.Append("<Y>" + Convert.ToBase64String(Y) + "</Y>");
            sb.Append("<MaxPlaintextBits>" + MaxPlaintextBits.ToString() + "</MaxPlaintextBits>");

            if (includePrivateParameters)
            {
                // we need to include X, which is the part of private key
                sb.Append("<X>" + Convert.ToBase64String(X) + "</X>");
            }

            sb.Append("</ElGamalKeyValue>");

            return sb.ToString();
        }
    }
}
