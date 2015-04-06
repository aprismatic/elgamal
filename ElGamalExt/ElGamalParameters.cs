/************************************************************************************
 This implementation of the ElGamal encryption scheme is based on the code from [1].
 It was changed and extended by Vasily Sidorov (http://bazzilic.me/).
 
 This code is provided as-is and is covered by the WTFPL 2.0 [2] (except for the
 parts that belong by O'Reilly - they are covered by [3]).
 
 
 [1] Adam Freeman & Allen Jones, Programming .NET Security: O'Reilly Media, 2003,
     ISBN 9780596552275 (http://books.google.com.sg/books?id=ykXCNVOIEuQC)
 
 [2] WTFPL – Do What the Fuck You Want to Public License, website,
     (http://wtfpl.net/)
 
 [3] Tim O'Reilly, O'Reilly Policy on Re-Use of Code Examples from Books: website,
     2001, (http://www.oreillynet.com/pub/a/oreilly/ask_tim/2001/codepolicy.html)
 ************************************************************************************/

using System;

namespace ElGamalExt
{
    [Serializable]
    public struct ElGamalParameters
    {
        public byte[] P;
        public byte[] G;
        public byte[] Y;
        public ElGamalPaddingMode Padding;

        [NonSerialized]
        public byte[] X;
    }
}
