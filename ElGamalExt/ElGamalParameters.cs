﻿using System;

namespace ElGamalExt
{
    [Serializable]
    public struct ElGamalParameters
    {
        public byte[] P;
        public byte[] G;
        public byte[] Y;

        public byte[] X;
    }
}
