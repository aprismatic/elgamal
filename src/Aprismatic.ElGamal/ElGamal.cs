﻿using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using Aprismatic.ElGamal.Homomorphism;

namespace Aprismatic.ElGamal
{
    public class ElGamal : AsymmetricAlgorithm
    {
        private readonly ElGamalKeyStruct keyStruct;

        public readonly ElGamalEncryptor Encryptor;
        public readonly ElGamalDecryptor Decryptor;

        public int MaxPlaintextBits => keyStruct.MaxPlaintextBits;
        public BigInteger MaxEncryptableValue => keyStruct.MaxEncryptableValue;
        public BigInteger P => keyStruct.P;
        public int PLength => keyStruct.PLength;
        public int CiphertextLength => keyStruct.CiphertextLength;


        #region Constructors & Key Generaion
        // TODO: Constructors should allow to specify MaxPlaintextBits
        public ElGamal(int keySize, int precomputedQueueSize = 10) // TODO: Constructor should probably optionally accept an RNG
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };
            KeySizeValue = keySize;

            if (!LegalKeySizesValue.Any(x => x.MinSize <= KeySizeValue && KeySizeValue <= x.MaxSize && (KeySizeValue - x.MinSize) % x.SkipSize == 0))
                throw new ArgumentException("Key size is not supported by this algorithm.");

            using var rng = RandomNumberGenerator.Create();
            var P = BigInteger.Zero.GenSafePseudoPrime(KeySizeValue, 16, rng); // Generate a large safe prime number P of key length KeySizeValue

            keyStruct = CreateKeyPair(P, ElGamalKeyDefaults.DefaultMaxPlaintextBits, rng);

            Encryptor = new ElGamalEncryptor(keyStruct, precomputedQueueSize);
            Decryptor = new ElGamalDecryptor(keyStruct);
        }

        public ElGamal(BigInteger safePrimeModulus, int precomputedQueueSize = 10)
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };
            KeySizeValue = safePrimeModulus.BitCount();

            if (!LegalKeySizesValue.Any(x => x.MinSize <= KeySizeValue && KeySizeValue <= x.MaxSize && (KeySizeValue - x.MinSize) % x.SkipSize == 0))
                throw new ArgumentException("Key size is not supported by this algorithm.");

            using var rng = RandomNumberGenerator.Create();

            if (! (safePrimeModulus.IsProbablePrime(4, rng) && ((safePrimeModulus - BigInteger.One) >> 1).IsProbablePrime(4, rng)) )
                throw new ArgumentException("Provided prime is not a safe prime.");

            keyStruct = CreateKeyPair(safePrimeModulus, ElGamalKeyDefaults.DefaultMaxPlaintextBits, rng);

            Encryptor = new ElGamalEncryptor(keyStruct, precomputedQueueSize);
            Decryptor = new ElGamalDecryptor(keyStruct);
        }

        public ElGamal(ElGamalParameters prms, int precomputedQueueSize = 10) // TODO: Consolidate constructors in one method
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };

            keyStruct = new ElGamalKeyStruct(
                new BigInteger(prms.P),
                new BigInteger(prms.G),
                new BigInteger(prms.Y),
                new BigInteger(prms.X),
                prms.MaxPlaintextBits
            );

            KeySizeValue = keyStruct.P.BitCount();

            if (!LegalKeySizesValue.Any(x => x.MinSize <= KeySizeValue && KeySizeValue <= x.MaxSize && (KeySizeValue - x.MinSize) % x.SkipSize == 0))
                throw new ArgumentException("Key size is not supported by this algorithm.");

            Encryptor = new ElGamalEncryptor(keyStruct, precomputedQueueSize);
            Decryptor = new ElGamalDecryptor(keyStruct);
        }

        public ElGamal(string xml, int precomputedQueueSize = 10) : this(ElGamalParameters.FromXml(xml), precomputedQueueSize)
        { }

        private ElGamalKeyStruct CreateKeyPair(BigInteger P, int maxptbits, RandomNumberGenerator rng) // TODO: This method should probably move to KeyStruct
        {
            // Good reading on the topic: https://ibm.github.io/system-security-research-updates/2021/07/20/insecurity-elgamal-pt1

            BigInteger G, Y, X;
            var bitwo = new BigInteger(2);
            var PminusOne = P - BigInteger.One;
            var Q = PminusOne / bitwo;

            // Find a generator (= a primitive root of group mod P)
            // G is a primitive root if for all prime factors of P-1, P[i], G^((P-1)/P[i]) (mod P) is not congruent to 1
            // Prime factors of (P-1) are 2 and (P-1)/2 because P = 2Q + 1, and Q is prime
            for (G = bitwo; G < PminusOne; G++)
            {
                if (!BigInteger.ModPow(G, bitwo, P).IsOne && !BigInteger.ModPow(G, Q, P).IsOne)
                    break;
            }

            // Generate the private key: a random number > 1 and < P-1
            X = BigInteger.Zero.GenRandomBits(bitwo, PminusOne, rng);

            // Generate the public key G^X mod P
            Y = BigInteger.ModPow(G, X, P);

            return new ElGamalKeyStruct(P, G, Y, X, maxptbits);
        }
        #endregion

        #region Encryption & Decryprtion
        public byte[] EncryptData(BigFraction message)
        {
            var ctbs = keyStruct.CiphertextBlocksize;
            var array = new byte[ctbs * 2];
            var arsp = array.AsSpan();

            Encryptor.ProcessBigInteger(Encode(message.Numerator), arsp[..ctbs]);
            Encryptor.ProcessBigInteger(Encode(message.Denominator), arsp[ctbs..]);

            return array;
        }

        public BigFraction DecryptData(ReadOnlySpan<byte> data)
        {
            var halfblock = data.Length >> 1;
            var quarterblock = halfblock >> 1;

            var numerator = Decryptor.ProcessByteBlock(data[..quarterblock], data[quarterblock..halfblock]);
            var denominator = Decryptor.ProcessByteBlock(data[halfblock..(halfblock + quarterblock)], data[(halfblock + quarterblock)..]);

            var res = new BigFraction(Decode(numerator), Decode(denominator));

            return res;
        }
        #endregion

        #region Homomorphic Properties
        // TODO: Consider moving Encode and Decode to a separate class library or to Homomorphism. This way, plaintext operations can be moved down to Homomorphism library
        public BigInteger Encode(BigInteger message) // TODO: Add tests now that this method is public
        {
            if (BigInteger.Abs(message) > keyStruct.MaxEncryptableValue)
                throw new ArgumentException($"Numerator or denominator of the fraction to encrypt are too large; should be |m| < 2^{keyStruct.MaxPlaintextBits - 1}");

            if (message.Sign < 0)
                return keyStruct.MaxRawPlaintext + message + BigInteger.One;
            return message;
        }

        public BigInteger Decode(BigInteger encodedMessage) // TODO: Add tests now that this method is public
        {
            encodedMessage %= keyStruct.MaxRawPlaintext + BigInteger.One;
            if (encodedMessage > keyStruct.MaxEncryptableValue)
                return encodedMessage - keyStruct.MaxRawPlaintext - BigInteger.One;
            return encodedMessage;
        }

        public byte[] Multiply(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second) => ElGamalHomomorphism.MultiplyFractions(first, second, keyStruct.P.ToByteArray());

        public byte[] Divide(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second) => ElGamalHomomorphism.DivideFractions(first, second, keyStruct.P.ToByteArray());

        // TODO: Examine ways of moving plaintext ops implementations to the Homomorphism class library
        public byte[] PlaintextMultiply(ReadOnlySpan<byte> first, BigFraction second) // TODO: Add overloads for BigInteger, Int32, Int64; same for PlaintextDivide
        {
            var res = new byte[first.Length];
            var ressp = res.AsSpan();

            var halfblock = first.Length >> 1;
            var quarterblock = halfblock >> 1;

            first[..quarterblock].CopyTo(ressp[..quarterblock]);
            first[halfblock..(halfblock + quarterblock)].CopyTo(ressp[halfblock..(halfblock + quarterblock)]);

            var nbb_bi = new BigInteger(first[quarterblock..halfblock]);
            var dbb_bi = new BigInteger(first[(halfblock + quarterblock)..]);

            nbb_bi = (nbb_bi * Encode(second.Numerator)) % keyStruct.P;
            dbb_bi = (dbb_bi * Encode(second.Denominator)) % keyStruct.P;

            nbb_bi.TryWriteBytes(ressp[quarterblock..halfblock], out _);
            dbb_bi.TryWriteBytes(ressp[(halfblock + quarterblock)..], out _);

            return res;
        }

        public byte[] PlaintextDivide(ReadOnlySpan<byte> first, BigFraction second) => PlaintextMultiply(first, new BigFraction(second.Denominator, second.Numerator));

        public byte[] PlaintextPow(ReadOnlySpan<byte> first, BigInteger exp_bi)
        {
            if (exp_bi.Sign == 0)
                return EncryptData(BigFraction.One);

            var halfblock = first.Length >> 1;

            if (exp_bi.Sign < 0) { // TODO: avoid copying
                // flip the encrypted fraction
                var flipped = new byte[first.Length];
                first[..halfblock].CopyTo(flipped[halfblock..]);
                first[halfblock..].CopyTo(flipped[..halfblock]);

                // power the flipped fraction
                var flipped_powed = PlaintextPow(flipped, -exp_bi);

                return Multiply(first, flipped_powed);
            }

            var numerator = first[..halfblock];
            var denominator = first[halfblock..];

            var res = new byte[first.Length];
            var ressp = res.AsSpan();
            var new_numerator = ressp[..halfblock];
            var new_denominator = ressp[halfblock..];

            PlaintextPowBigInteger(numerator, exp_bi, new_numerator);
            PlaintextPowBigInteger(denominator, exp_bi, new_denominator);

            return res;
        }

        public void PlaintextPowBigInteger(ReadOnlySpan<byte> first, BigInteger exp_bi, Span<byte> writeTo)
        {
            if (exp_bi.Sign < 0) throw new ArgumentOutOfRangeException(nameof(exp_bi), "Exponent should be >= 0");

            var halfblock = first.Length >> 1;

            var a_bi = new BigInteger(first[..halfblock]);
            var b_bi = new BigInteger(first[halfblock..]);

            a_bi = BigInteger.ModPow(a_bi, exp_bi, keyStruct.P);
            b_bi = BigInteger.ModPow(b_bi, exp_bi, keyStruct.P);

            a_bi.TryWriteBytes(writeTo[..halfblock], out _);
            b_bi.TryWriteBytes(writeTo[halfblock..], out _);
        }
        #endregion

        #region Serialization
        public ElGamalParameters ExportParameters(bool includePrivateParams) => keyStruct.ExportParameters(includePrivateParams);

        public override string ToXmlString(bool includePrivateParameters)
        {
            var prms = ExportParameters(includePrivateParameters);
            return prms.ToXml(includePrivateParameters);
        }
        #endregion

        public new void Dispose() => Encryptor.Dispose();
    }
}
