﻿using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Channels;

namespace Aprismatic.ElGamal
{
    public class ElGamalEncryptor : IDisposable
    {
        private readonly RandomNumberGenerator _rng;
        private readonly ElGamalKeyStruct _keyStruct;

        private readonly bool _isPrecomputed;
        private Channel<(BigInteger, BigInteger)> _encPrecomputedChannel;
        private Task _encPrecomputeTask;
        private CancellationTokenSource _encPrecomputeCts;

        public ElGamalEncryptor(ElGamalKeyStruct keyStruct, int precomputedSize = 10)
        {
            if (precomputedSize < 0)
                throw new ArgumentOutOfRangeException(nameof(precomputedSize), precomputedSize, "Queue size for precomputed values can't be < 0");

            _rng = RandomNumberGenerator.Create();
            _keyStruct = keyStruct;

            if (precomputedSize > 0)
            {
                _isPrecomputed = true;

                var opts = new BoundedChannelOptions(2 * precomputedSize + 1) // double as we encrypt (numerator, denominator) for each
                {
                    FullMode = BoundedChannelFullMode.Wait,
                    SingleReader = true,
                    SingleWriter = true
                };
                _encPrecomputedChannel = Channel.CreateBounded<(BigInteger, BigInteger)>(opts);

                _encPrecomputeCts = new CancellationTokenSource();
                var token = _encPrecomputeCts.Token;
                _encPrecomputeTask = Task.Run(() => PrecomputeValuesTask(token));
            }
            else
            {
                _isPrecomputed = false;
                _encPrecomputeTask = null;
                _encPrecomputedChannel = null;
                _encPrecomputeCts = null;
            }
        }

        private void PrecomputeValuesTask(CancellationToken token)
        {
            while (true)
            {
                if (token.IsCancellationRequested) return;

                var (gkp, ykp) = ComputeValuePair();

                try { _encPrecomputedChannel.Writer.WriteAsync((gkp, ykp), token).AsTask().Wait(token); }
                catch (OperationCanceledException) { return; }
            }
        }

        private (BigInteger, BigInteger) ComputeValuePair()
        {
            BigInteger K;

            // Generate the private key: a random number > 1 and < P-1
            var PminusOne = _keyStruct.P - BigInteger.One;
            do
            {
                K = BigInteger.Zero.GenRandomBits(_keyStruct.PBitCount, _rng);
            } while (K <= BigInteger.One || K >= PminusOne);

            var gkp = BigInteger.ModPow(_keyStruct.G, K, _keyStruct.P);
            var ykp = BigInteger.ModPow(_keyStruct.Y, K, _keyStruct.P);

            return (gkp, ykp);
        }

        public void ProcessBigInteger(BigInteger encodedMessage, Span<byte> writeTo)
        {
            if (!_isPrecomputed || !_encPrecomputedChannel.Reader.TryRead(out var vp))
                vp = ComputeValuePair();
            var (gkp, ykp) = vp;

            var A = gkp;
            var B = (ykp * encodedMessage) % _keyStruct.P;

            var halfblock = _keyStruct.CiphertextBlocksize >> 1;
            A.TryWriteBytes(writeTo[..halfblock], out _);
            B.TryWriteBytes(writeTo[halfblock..], out _);
        }

        public void Dispose()
        {
            if (_isPrecomputed)
            {
                _encPrecomputeCts.Cancel();
                _encPrecomputeTask.Wait();
                _encPrecomputeCts.Dispose();
                _encPrecomputeTask.Dispose();
            }

            _rng.Dispose();
        }
    }
}
