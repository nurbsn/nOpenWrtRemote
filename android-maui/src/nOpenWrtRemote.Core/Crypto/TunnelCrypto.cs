using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using NBitcoin.Secp256k1;

namespace nOpenWrtRemote.Core.Crypto;

/// <summary>
/// Ephemeral secp256k1 ECDH + HKDF-SHA256 + directional AES-256-GCM tunnel encryption with strict monotonic anti-replay.
/// </summary>
public sealed class TunnelCrypto : IDisposable
{
    public const byte DirClientToRouter = 0x01;
    public const byte DirRouterToClient = 0x02;
    private const int TagSize = 16;

    private static readonly byte[] ProtocolTag = Encoding.ASCII.GetBytes("NORT-1");
    private static readonly byte[] InfoC2R = Encoding.ASCII.GetBytes("nort-c2r-aes256gcm");
    private static readonly byte[] InfoR2C = Encoding.ASCII.GetBytes("nort-r2c-aes256gcm");

    private readonly byte[] _sessionIdBytes;
    private readonly bool _isRouter;
    private readonly AesGcm _c2r;
    private readonly AesGcm _r2c;
    private readonly Lock _txLock = new();
    private readonly Lock _rxLock = new();

    private ulong _txSeq;
    private ulong _lastRxSeq;

    public TunnelCrypto(
        bool isRouter,
        ReadOnlySpan<byte> localEphPriv32,
        ReadOnlySpan<byte> remoteEphXOnlyPub32,
        ReadOnlySpan<byte> clientIdentityPub32,
        ReadOnlySpan<byte> routerIdentityPub32,
        string sessionId,
        ReadOnlySpan<byte> clientEphPub32,
        ReadOnlySpan<byte> routerEphPub32)
    {
        if (localEphPriv32.Length != 32 || remoteEphXOnlyPub32.Length != 32 ||
            clientIdentityPub32.Length != 32 || routerIdentityPub32.Length != 32 ||
            clientEphPub32.Length != 32 || routerEphPub32.Length != 32)
        {
            throw new ArgumentException("All secp256k1 keys must be 32 bytes.");
        }

        if (!ECPrivKey.TryCreate(localEphPriv32, out var privKey) || privKey is null)
            throw new ArgumentException("Invalid local ephemeral private key.", nameof(localEphPriv32));

        Span<byte> compressed = stackalloc byte[33];
        compressed[0] = 0x02;
        remoteEphXOnlyPub32.CopyTo(compressed[1..]);
        if (!ECPubKey.TryCreate(compressed, Context.Instance, out _, out var remotePub) || remotePub is null)
            throw new ArgumentException("Invalid remote ephemeral public key.", nameof(remoteEphXOnlyPub32));

        var sharedPoint = remotePub.GetSharedPubkey(privKey);
        Span<byte> sharedCompressed = stackalloc byte[33];
        sharedPoint.WriteToSpan(true, sharedCompressed, out _);

        _sessionIdBytes = Encoding.UTF8.GetBytes(sessionId);
        _isRouter = isRouter;

        using var transcript = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        transcript.AppendData(ProtocolTag);
        transcript.AppendData(clientIdentityPub32);
        transcript.AppendData(routerIdentityPub32);
        transcript.AppendData(_sessionIdBytes);
        transcript.AppendData(clientEphPub32);
        transcript.AppendData(routerEphPub32);
        byte[] transcriptHash = transcript.GetHashAndReset();

        byte[] prk = HKDF.Extract(HashAlgorithmName.SHA256, sharedCompressed[1..].ToArray(), transcriptHash);
        byte[] keyC2R = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, InfoC2R);
        byte[] keyR2C = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, InfoR2C);

        _c2r = new AesGcm(keyC2R, TagSize);
        _r2c = new AesGcm(keyR2C, TagSize);
    }

    public byte[] Seal(ReadOnlySpan<byte> plaintext)
    {
        ulong seq;
        lock (_txLock)
        {
            _txSeq++;
            seq = _txSeq;
        }

        byte dir = _isRouter ? DirRouterToClient : DirClientToRouter;
        AesGcm aead = _isRouter ? _r2c : _c2r;

        Span<byte> nonce = stackalloc byte[12];
        nonce[..4].Clear();
        BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], seq);

        Span<byte> aad = stackalloc byte[_sessionIdBytes.Length + 9];
        _sessionIdBytes.CopyTo(aad);
        aad[_sessionIdBytes.Length] = dir;
        BinaryPrimitives.WriteUInt64BigEndian(aad[(_sessionIdBytes.Length + 1)..], seq);

        byte[] envelope = new byte[9 + plaintext.Length + TagSize];
        envelope[0] = dir;
        BinaryPrimitives.WriteUInt64BigEndian(envelope.AsSpan(1, 8), seq);

        aead.Encrypt(
            nonce,
            plaintext,
            envelope.AsSpan(9, plaintext.Length),
            envelope.AsSpan(9 + plaintext.Length, TagSize),
            aad);

        return envelope;
    }

    public byte[] Open(ReadOnlySpan<byte> envelope)
    {
        if (envelope.Length < 9 + TagSize)
            throw new CryptographicException("Tunnel envelope too short.");

        byte dir = envelope[0];
        ulong seq = BinaryPrimitives.ReadUInt64BigEndian(envelope.Slice(1, 8));

        byte expectedDir = _isRouter ? DirClientToRouter : DirRouterToClient;
        if (dir != expectedDir)
            throw new CryptographicException($"Unexpected frame direction: 0x{dir:X2}.");

        AesGcm aead = _isRouter ? _c2r : _r2c;

        Span<byte> nonce = stackalloc byte[12];
        nonce[..4].Clear();
        BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], seq);

        Span<byte> aad = stackalloc byte[_sessionIdBytes.Length + 9];
        _sessionIdBytes.CopyTo(aad);
        aad[_sessionIdBytes.Length] = dir;
        BinaryPrimitives.WriteUInt64BigEndian(aad[(_sessionIdBytes.Length + 1)..], seq);

        int cipherLen = envelope.Length - 9 - TagSize;
        byte[] plaintext = new byte[cipherLen];

        lock (_rxLock)
        {
            if (seq == 0 || seq <= _lastRxSeq)
                throw new CryptographicException($"Replay or out-of-order frame detected (seq={seq}, last={_lastRxSeq}).");

            aead.Decrypt(
                nonce,
                envelope.Slice(9, cipherLen),
                envelope.Slice(9 + cipherLen, TagSize),
                plaintext,
                aad);

            _lastRxSeq = seq;
        }

        return plaintext;
    }

    public void Dispose()
    {
        _c2r.Dispose();
        _r2c.Dispose();
    }
}
