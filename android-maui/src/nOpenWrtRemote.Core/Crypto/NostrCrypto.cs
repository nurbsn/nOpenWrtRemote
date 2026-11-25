using System.Security.Cryptography;
using NBitcoin.Secp256k1;

namespace nOpenWrtRemote.Core.Crypto;

public static class NostrCrypto
{
    public static (byte[] PrivKey32, byte[] XOnlyPubKey32) GenerateKeyPair()
    {
        while (true)
        {
            byte[] candidate = RandomNumberGenerator.GetBytes(32);
            if (ECPrivKey.TryCreate(candidate, out var privKey) && privKey is not null)
            {
                byte[] xOnly = GetXOnlyPubKey(privKey);
                return (candidate, xOnly);
            }
        }
    }

    public static byte[] GetXOnlyPubKey(ReadOnlySpan<byte> privKey32)
    {
        if (!ECPrivKey.TryCreate(privKey32, out var privKey) || privKey is null)
            throw new ArgumentException("Invalid secp256k1 private key.", nameof(privKey32));
        return GetXOnlyPubKey(privKey);
    }

    private static byte[] GetXOnlyPubKey(ECPrivKey privKey)
    {
        var xOnly = privKey.CreateXOnlyPubKey();
        return xOnly.ToBytes();
    }

    public static byte[] SignBip340(ReadOnlySpan<byte> msgHash32, ReadOnlySpan<byte> privKey32)
    {
        if (msgHash32.Length != 32)
            throw new ArgumentException("Message hash must be 32 bytes.", nameof(msgHash32));
        if (!ECPrivKey.TryCreate(privKey32, out var privKey) || privKey is null)
            throw new ArgumentException("Invalid secp256k1 private key.", nameof(privKey32));

        var sig = privKey.SignBIP340(msgHash32);
        return sig.ToBytes();
    }

    public static bool VerifyBip340(ReadOnlySpan<byte> msgHash32, ReadOnlySpan<byte> sig64, ReadOnlySpan<byte> xOnlyPubKey32)
    {
        if (msgHash32.Length != 32 || sig64.Length != 64 || xOnlyPubKey32.Length != 32)
            return false;

        if (!ECXOnlyPubKey.TryCreate(xOnlyPubKey32, out var pubKey) || pubKey is null)
            return false;

        if (!SecpSchnorrSignature.TryCreate(sig64, out var sig) || sig is null)
            return false;

        return pubKey.SigVerifyBIP340(sig, msgHash32);
    }
}
