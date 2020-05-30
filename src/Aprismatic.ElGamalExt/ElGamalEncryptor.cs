using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Channels;

namespace Aprismatic.ElGamalExt
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

            {
                var KSize = _keyStruct.PBitCount - 1;
                var PMinusOne = _keyStruct.P - BigInteger.One;
                do
                {
                    K = BigInteger.Zero.GenRandomBits(KSize, _rng);
                } while (!BigInteger.GreatestCommonDivisor(K, PMinusOne).IsOne);
            }

            var gkp = BigInteger.ModPow(_keyStruct.G, K, _keyStruct.P);
            var ykp = BigInteger.ModPow(_keyStruct.Y, K, _keyStruct.P);

            return (gkp, ykp);
        }

        public void ProcessBigInteger(BigInteger message, Span<byte> WriteTo)
        {
            if (BigInteger.Abs(message) > ElGamalKeyStruct.MaxEncryptableValue)
                throw new ArgumentException($"Message to encrypt is too large. Message should be |m| < 2^{ElGamalKeyStruct.MaxPlaintextBits - 1}");

            if (!_isPrecomputed || !_encPrecomputedChannel.Reader.TryRead(out var vp))
                vp = ComputeValuePair();
            var (gkp, ykp) = vp;

            var A = gkp;
            var B = ykp * Encode(message) % _keyStruct.P;

            var halfblock = _keyStruct.CiphertextBlocksize >> 1;
            A.TryWriteBytes(WriteTo.Slice(0, halfblock), out _);
            B.TryWriteBytes(WriteTo.Slice(halfblock, halfblock), out _);
        }

        private BigInteger Encode(BigInteger origin)
        {
            if (origin.Sign < 0)
                return ElGamalKeyStruct.MaxRawPlaintext + origin + BigInteger.One;
            return origin;
        }

        public void Dispose()
        {
            _rng.Dispose();

            if (_isPrecomputed)
            {
                _encPrecomputeCts.Cancel();
                _encPrecomputeTask.Wait();
                _encPrecomputeCts.Dispose();
                _encPrecomputeTask.Dispose();
            }
        }
    }
}
