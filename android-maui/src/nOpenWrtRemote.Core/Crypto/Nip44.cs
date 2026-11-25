using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using NBitcoin.Secp256k1;

namespace nOpenWrtRemote.Core.Crypto;

/// <summary>
/// Spec-compliant NIP-44 v2 encrypted payload implementation (secp256k1 ECDH + HKDF-SHA256 + ChaCha20 + HMAC-SHA256).
/// </summary>
public static class Nip44
{
    private const byte Version2 = 2;
    private const int MinPlaintextLen = 1;
    private const int MaxPlaintextLen = 65535;
    private static readonly byte[] SaltV2 = Encoding.ASCII.GetBytes("nip44-v2");

    public static int CalcPaddedLen(int unpaddedLen)
    {
        if (unpaddedLen < MinPlaintextLen || unpaddedLen > MaxPlaintextLen)
            throw new ArgumentOutOfRangeException(nameof(unpaddedLen), "Plaintext length must be 1..65535 bytes.");

        if (unpaddedLen <= 32)
            return 32;

        int nextPower = 1 << (BitOperations.Log2((uint)(unpaddedLen - 1)) + 1);
        int chunk = nextPower <= 256 ? 32 : nextPower / 8;
        return chunk * (((unpaddedLen - 1) / chunk) + 1);
    }

    public static byte[] GetConversationKey(ReadOnlySpan<byte> privKey32, ReadOnlySpan<byte> peerXOnlyPub32)
    {
        if (privKey32.Length != 32) throw new ArgumentException("Private key must be 32 bytes.", nameof(privKey32));
        if (peerXOnlyPub32.Length != 32) throw new ArgumentException("Peer x-only pubkey must be 32 bytes.", nameof(peerXOnlyPub32));

        if (!ECPrivKey.TryCreate(privKey32, out var privKey) || privKey is null)
            throw new ArgumentException("Invalid secp256k1 private key.", nameof(privKey32));

        Span<byte> compressed = stackalloc byte[33];
        compressed[0] = 0x02;
        peerXOnlyPub32.CopyTo(compressed[1..]);

        if (!ECPubKey.TryCreate(compressed, Context.Instance, out _, out var peerPub) || peerPub is null)
            throw new ArgumentException("Invalid secp256k1 public key.", nameof(peerXOnlyPub32));

        var sharedPoint = peerPub.GetSharedPubkey(privKey);
        Span<byte> sharedCompressed = stackalloc byte[33];
        sharedPoint.WriteToSpan(true, sharedCompressed, out _);
        // NIP-44 takes the raw 32-byte x-coordinate (bytes 1..33) as IKM to HKDF-Extract.
        return HKDF.Extract(HashAlgorithmName.SHA256, sharedCompressed[1..].ToArray(), SaltV2);
    }

    public static string Encrypt(string plaintext, ReadOnlySpan<byte> conversationKey32, ReadOnlySpan<byte> nonce32 = default)
    {
        byte[] nonce = nonce32.IsEmpty ? RandomNumberGenerator.GetBytes(32) : nonce32.ToArray();
        if (nonce.Length != 32)
            throw new ArgumentException("Nonce must be 32 bytes.", nameof(nonce32));

        byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
        int paddedLen = CalcPaddedLen(plainBytes.Length);

        byte[] padded = new byte[2 + paddedLen];
        BinaryPrimitives.WriteUInt16BigEndian(padded.AsSpan(0, 2), (ushort)plainBytes.Length);
        plainBytes.CopyTo(padded, 2);

        DeriveMessageKeys(conversationKey32, nonce, out var chachaKey, out var chachaNonce, out var hmacKey);

        byte[] ciphertext = ChaCha20.Transform(chachaKey, chachaNonce, 0u, padded);
        byte[] mac = ComputeHmacAad(hmacKey, nonce, ciphertext);

        byte[] envelope = new byte[1 + 32 + ciphertext.Length + 32];
        envelope[0] = Version2;
        nonce.CopyTo(envelope, 1);
        ciphertext.CopyTo(envelope, 33);
        mac.CopyTo(envelope, 33 + ciphertext.Length);

        return Convert.ToBase64String(envelope);
    }

    public static string Decrypt(string payload, ReadOnlySpan<byte> conversationKey32)
    {
        if (string.IsNullOrEmpty(payload) || payload[0] == '#')
            throw new CryptographicException("Unsupported NIP-44 payload.");

        byte[] raw = Convert.FromBase64String(payload);
        if (raw.Length < 99 || raw.Length > 65603)
            throw new CryptographicException("Invalid NIP-44 payload length.");
        if (raw[0] != Version2)
            throw new CryptographicException($"Unsupported NIP-44 version: {raw[0]}.");

        ReadOnlySpan<byte> nonce = raw.AsSpan(1, 32);
        ReadOnlySpan<byte> ciphertext = raw.AsSpan(33, raw.Length - 65);
        ReadOnlySpan<byte> mac = raw.AsSpan(raw.Length - 32, 32);

        DeriveMessageKeys(conversationKey32, nonce, out var chachaKey, out var chachaNonce, out var hmacKey);
        byte[] expectedMac = ComputeHmacAad(hmacKey, nonce, ciphertext);

        if (!CryptographicOperations.FixedTimeEquals(mac, expectedMac))
            throw new CryptographicException("NIP-44 HMAC verification failed.");

        byte[] padded = ChaCha20.Transform(chachaKey, chachaNonce, 0u, ciphertext);
        if (padded.Length < 2)
            throw new CryptographicException("Truncated NIP-44 plaintext.");

        int unpaddedLen = BinaryPrimitives.ReadUInt16BigEndian(padded.AsSpan(0, 2));
        if (unpaddedLen < MinPlaintextLen || padded.Length != 2 + CalcPaddedLen(unpaddedLen))
            throw new CryptographicException("Invalid NIP-44 padding.");

        return Encoding.UTF8.GetString(padded, 2, unpaddedLen);
    }

    private static void DeriveMessageKeys(
        ReadOnlySpan<byte> conversationKey32,
        ReadOnlySpan<byte> nonce32,
        out byte[] chachaKey,
        out byte[] chachaNonce,
        out byte[] hmacKey)
    {
        if (conversationKey32.Length != 32)
            throw new ArgumentException("Conversation key must be 32 bytes.", nameof(conversationKey32));
        if (nonce32.Length != 32)
            throw new ArgumentException("Nonce must be 32 bytes.", nameof(nonce32));

        byte[] okm = HKDF.Expand(HashAlgorithmName.SHA256, conversationKey32.ToArray(), 76, nonce32.ToArray());
        chachaKey = okm[..32];
        chachaNonce = okm[32..44];
        hmacKey = okm[44..76];
    }

    private static byte[] ComputeHmacAad(byte[] hmacKey, ReadOnlySpan<byte> nonce32, ReadOnlySpan<byte> ciphertext)
    {
        using var hmac = new System.Security.Cryptography.HMACSHA256(hmacKey);
        byte[] input = new byte[nonce32.Length + ciphertext.Length];
        nonce32.CopyTo(input);
        ciphertext.CopyTo(input.AsSpan(nonce32.Length));
        return hmac.ComputeHash(input);
    }
}
