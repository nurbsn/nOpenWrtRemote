using System.Buffers.Binary;
using System.Numerics;

namespace nOpenWrtRemote.Core.Crypto;

/// <summary>
/// RFC 8439 IETF ChaCha20 stream cipher (32-byte key, 12-byte nonce, 32-bit block counter).
/// </summary>
public static class ChaCha20
{
    public static byte[] Transform(
        ReadOnlySpan<byte> key32,
        ReadOnlySpan<byte> nonce12,
        uint initialCounter,
        ReadOnlySpan<byte> input)
    {
        if (key32.Length != 32) throw new ArgumentException("Key must be 32 bytes.", nameof(key32));
        if (nonce12.Length != 12) throw new ArgumentException("Nonce must be 12 bytes.", nameof(nonce12));

        var output = new byte[input.Length];
        Span<uint> state = stackalloc uint[16];
        Span<uint> working = stackalloc uint[16];
        Span<byte> keystream = stackalloc byte[64];

        uint counter = initialCounter;
        int offset = 0;

        while (offset < input.Length)
        {
            state[0] = 0x61707865u;
            state[1] = 0x3320646eu;
            state[2] = 0x79622d32u;
            state[3] = 0x6b206574u;

            for (int i = 0; i < 8; i++)
                state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key32.Slice(i * 4, 4));

            state[12] = counter;
            state[13] = BinaryPrimitives.ReadUInt32LittleEndian(nonce12.Slice(0, 4));
            state[14] = BinaryPrimitives.ReadUInt32LittleEndian(nonce12.Slice(4, 4));
            state[15] = BinaryPrimitives.ReadUInt32LittleEndian(nonce12.Slice(8, 4));

            state.CopyTo(working);

            for (int round = 0; round < 10; round++)
            {
                QuarterRound(working, 0, 4, 8, 12);
                QuarterRound(working, 1, 5, 9, 13);
                QuarterRound(working, 2, 6, 10, 14);
                QuarterRound(working, 3, 7, 11, 15);
                QuarterRound(working, 0, 5, 10, 15);
                QuarterRound(working, 1, 6, 11, 12);
                QuarterRound(working, 2, 7, 8, 13);
                QuarterRound(working, 3, 4, 9, 14);
            }

            for (int i = 0; i < 16; i++)
            {
                uint sum = working[i] + state[i];
                BinaryPrimitives.WriteUInt32LittleEndian(keystream.Slice(i * 4, 4), sum);
            }

            int chunk = Math.Min(64, input.Length - offset);
            for (int i = 0; i < chunk; i++)
                output[offset + i] = (byte)(input[offset + i] ^ keystream[i]);

            offset += chunk;
            counter++;
        }

        return output;
    }

    private static void QuarterRound(Span<uint> x, int a, int b, int c, int d)
    {
        x[a] += x[b]; x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 7);
    }
}
