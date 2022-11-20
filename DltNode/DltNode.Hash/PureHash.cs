using System;

namespace DltNode.Hash
{
    public class PureHash
    {
        private ulong[] _keccakRoundConstants =
        {
            0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
            0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
            0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
            0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
            0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
            0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
        };

        private int _outputLength = 256;
        private int _rate = 1088;
        private int _digestSize = 32;
        
        private int _bitsInQueue;
        private byte[] _dataQueue = new byte[192];
        private ulong[] _state = new ulong[25];

        public byte[] ComputeHash(byte[] input)
        {
            _absorb(input, 0, input.Length);
            byte[] output = new byte[32];

            _doFinal(output, 0);


            return output;
        }

        private void _uintToByte(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)n;
            bs[off + 1] = (byte)(n >> 8);
            bs[off + 2] = (byte)(n >> 16);
            bs[off + 3] = (byte)(n >> 24);
        }

        private uint _byteToUInt(byte[] bs, int off)
        {
            return bs[off]
                   | ((uint)bs[off + 1] << 8)
                   | ((uint)bs[off + 2] << 16)
                   | ((uint)bs[off + 3] << 24);
        }

        private void _uint64ToByte(ulong n, byte[] bs, int off)
        {
            _uintToByte((uint)n, bs, off);
            _uintToByte((uint)(n >> 32), bs, off + 4);
        }

        private void _uint64ToByte(ulong[] ns, int nsOff, int nsLen, byte[] bs, int bsOff)
        {
            for (int i = 0; i < nsLen; ++i)
            {
                _uint64ToByte(ns[nsOff + i], bs, bsOff);
                bsOff += 8;
            }
        }

        private ulong _byteToUInt64(byte[] bs, int off)
        {
            uint lo = _byteToUInt(bs, off);
            uint hi = _byteToUInt(bs, off + 4);
            return ((ulong)hi << 32) | lo;
        }

        private int _doFinal(byte[] output, int outOff)
        {
            _squeeze(output, outOff);

            _reset();

            return _digestSize;
        }

        private void _reset()
        {
            Array.Clear(_state, 0, _state.Length);
            Array.Clear(_dataQueue, 0, _dataQueue.Length);
            _bitsInQueue = 0;
        }

        private void _absorb(byte[] data, int off, int len)
        {
            var bytesInQueue = _bitsInQueue >> 3;
            var rateBytes = _rate >> 3;

            var available = rateBytes - bytesInQueue;
            if (len < available)
            {
                Array.Copy(data, off, _dataQueue, bytesInQueue, len);
                _bitsInQueue += len << 3;
                return;
            }

            var count = 0;
            if (bytesInQueue > 0)
            {
                Array.Copy(data, off, _dataQueue, bytesInQueue, available);
                count += available;
                _keccakAbsorb(_dataQueue, 0);
            }

            int remaining;
            while ((remaining = len - count) >= rateBytes)
            {
                _keccakAbsorb(data, off + count);
                count += rateBytes;
            }

            Array.Copy(data, off + count, _dataQueue, 0, remaining);
            _bitsInQueue = remaining << 3;
        }

        private void _helperToSqueezingPhase()
        {
            _dataQueue[_bitsInQueue >> 3] |= (byte)(1 << (_bitsInQueue & 7));

            if (++_bitsInQueue == _rate)
            {
                _keccakAbsorb(_dataQueue, 0);
            }
            else
            {
                int full = _bitsInQueue >> 6, partial = _bitsInQueue & 63;
                var off = 0;
                for (var i = 0; i < full; ++i)
                {
                    _state[i] ^= _byteToUInt64(_dataQueue, off);
                    off += 8;
                }

                if (partial > 0)
                {
                    var mask = (1UL << partial) - 1UL;
                    _state[full] ^= _byteToUInt64(_dataQueue, off) & mask;
                }
            }

            _state[(_rate - 1) >> 6] ^= 1UL << 63;

            _bitsInQueue = 0;
        }

        private void _squeeze(byte[] output, int offset)
        {
            _helperToSqueezingPhase();

            if ((_outputLength & 7L) != 0L)
            {
                throw new InvalidOperationException("outputLength not a multiple of 8");
            }

            long i = 0;
            while (i < _outputLength)
            {
                if (_bitsInQueue == 0)
                {
                    _extract();
                }

                int partialBlock = (int)Math.Min(_bitsInQueue, _outputLength - i);
                Array.Copy(_dataQueue, (_rate - _bitsInQueue) >> 3, output, offset + (int)(i >> 3), partialBlock >> 3);
                _bitsInQueue -= partialBlock;
                i += partialBlock;
            }
        }

        private void _keccakAbsorb(byte[] data, int off)
        {
            var count = _rate >> 6;
            for (var i = 0; i < count; ++i)
            {
                _state[i] ^= _byteToUInt64(data, off);
                off += 8;
            }

            _replacement();
        }

        private void _extract()
        {
            _replacement();

            _uint64ToByte(_state, 0, _rate >> 6, _dataQueue, 0);

            _bitsInQueue = _rate;
        }

        private void _replacement()
        {
            ulong[] a = _state;

            ulong a00 = a[0];
            ulong a01 = a[1];
            ulong a02 = a[2];
            ulong a03 = a[3];
            ulong a04 = a[4];
            ulong a05 = a[5];
            ulong a06 = a[6];
            ulong a07 = a[7];
            ulong a08 = a[8];
            ulong a09 = a[9];
            ulong a10 = a[10];
            ulong a11 = a[11];
            ulong a12 = a[12];
            ulong a13 = a[13]; 
            ulong a14 = a[14];
            ulong a15 = a[15];
            ulong a16 = a[16];
            ulong a17 = a[17];
            ulong a18 = a[18];
            ulong a19 = a[19];
            ulong a20 = a[20];
            ulong a21 = a[21];
            ulong a22 = a[22];
            ulong a23 = a[23];
            ulong  a24 = a[24];

            for (int i = 0; i < 24; i++)
            {
                ulong c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
                ulong c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
                ulong c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
                ulong c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
                ulong c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;

                ulong d1 = ((c1 << 1) | (c1 >> -1)) ^ c4;
                ulong d2 = ((c2 << 1) | (c2 >> -1)) ^ c0;
                ulong d3 = ((c3 << 1) | (c3 >> -1)) ^ c1;
                ulong d4 = ((c4 << 1) | (c4 >> -1)) ^ c2;
                ulong d0 = ((c0 << 1) | (c0 >> -1)) ^ c3;

                a00 ^= d1;
                a05 ^= d1;
                a10 ^= d1;
                a15 ^= d1;
                a20 ^= d1;
                a01 ^= d2;
                a06 ^= d2;
                a11 ^= d2;
                a16 ^= d2;
                a21 ^= d2;
                a02 ^= d3;
                a07 ^= d3;
                a12 ^= d3;
                a17 ^= d3;
                a22 ^= d3;
                a03 ^= d4;
                a08 ^= d4;
                a13 ^= d4;
                a18 ^= d4;
                a23 ^= d4;
                a04 ^= d0;
                a09 ^= d0;
                a14 ^= d0;
                a19 ^= d0;
                a24 ^= d0;

                c1 = (a01 << 1) | (a01 >> 63);
                a01 = (a06 << 44) | (a06 >> 20);
                a06 = (a09 << 20) | (a09 >> 44);
                a09 = (a22 << 61) | (a22 >> 3);
                a22 = (a14 << 39) | (a14 >> 25);
                a14 = (a20 << 18) | (a20 >> 46);
                a20 = (a02 << 62) | (a02 >> 2);
                a02 = (a12 << 43) | (a12 >> 21);
                a12 = (a13 << 25) | (a13 >> 39);
                a13 = (a19 << 8) | (a19 >> 56);
                a19 = (a23 << 56) | (a23 >> 8);
                a23 = (a15 << 41) | (a15 >> 23);
                a15 = (a04 << 27) | (a04 >> 37);
                a04 = (a24 << 14) | (a24 >> 50);
                a24 = (a21 << 2) | (a21 >> 62);
                a21 = (a08 << 55) | (a08 >> 9);
                a08 = (a16 << 45) | (a16 >> 19);
                a16 = (a05 << 36) | (a05 >> 28);
                a05 = (a03 << 28) | (a03 >> 36);
                a03 = (a18 << 21) | (a18 >> 43);
                a18 = (a17 << 15) | (a17 >> 49);
                a17 = (a11 << 10) | (a11 >> 54);
                a11 = (a07 << 6) | (a07 >> 58);
                a07 = (a10 << 3) | (a10 >> 61);
                a10 = c1;

                c0 = a00 ^ (~a01 & a02);
                c1 = a01 ^ (~a02 & a03);
                a02 ^= ~a03 & a04;
                a03 ^= ~a04 & a00;
                a04 ^= ~a00 & a01;
                a00 = c0;
                a01 = c1;
                c0 = a05 ^ (~a06 & a07);
                c1 = a06 ^ (~a07 & a08);
                a07 ^= ~a08 & a09;
                a08 ^= ~a09 & a05;
                a09 ^= ~a05 & a06;
                a05 = c0;
                a06 = c1;
                c0 = a10 ^ (~a11 & a12);
                c1 = a11 ^ (~a12 & a13);
                a12 ^= ~a13 & a14;
                a13 ^= ~a14 & a10;
                a14 ^= ~a10 & a11;
                a10 = c0;
                a11 = c1;
                c0 = a15 ^ (~a16 & a17);
                c1 = a16 ^ (~a17 & a18);
                a17 ^= ~a18 & a19;
                a18 ^= ~a19 & a15;
                a19 ^= ~a15 & a16;
                a15 = c0;
                a16 = c1;
                c0 = a20 ^ (~a21 & a22);
                c1 = a21 ^ (~a22 & a23);
                a22 ^= ~a23 & a24;
                a23 ^= ~a24 & a20;
                a24 ^= ~a20 & a21;
                a20 = c0;
                a21 = c1;
                a00 ^= _keccakRoundConstants[i];
            }

            a[0] = a00;
            a[1] = a01;
            a[2] = a02;
            a[3] = a03;
            a[4] = a04;
            a[5] = a05;
            a[6] = a06;
            a[7] = a07;
            a[8] = a08;
            a[9] = a09;
            a[10] = a10;
            a[11] = a11;
            a[12] = a12;
            a[13] = a13;
            a[14] = a14;
            a[15] = a15;
            a[16] = a16;
            a[17] = a17;
            a[18] = a18;
            a[19] = a19;
            a[20] = a20;
            a[21] = a21;
            a[22] = a22;
            a[23] = a23;
            a[24] = a24;
        }
    }
}