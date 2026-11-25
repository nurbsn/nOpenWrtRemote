using nOpenWrtRemote.Core.Crypto;

namespace nOpenWrtRemote.App.Services;

public static class DeepLinkInbox
{
    private static string? _pendingPairUri;
    public static event Action<string>? PairUriReceived;

    public static void SetPendingPairUri(string uri)
    {
        _pendingPairUri = uri;
        PairUriReceived?.Invoke(uri);
    }

    public static string? ConsumePendingPairUri()
    {
        string? val = _pendingPairUri;
        _pendingPairUri = null;
        return val;
    }
}

public sealed class IdentityService
{
    private const string PrivKeyStorageKey = "nort_identity_priv_hex_v1";
    private byte[]? _cachedPrivKey;

    public async Task<byte[]> GetOrCreatePrivateKeyAsync()
    {
        if (_cachedPrivKey is not null)
            return _cachedPrivKey;

        string? hex = await SecureStorage.Default.GetAsync(PrivKeyStorageKey);
        if (!string.IsNullOrWhiteSpace(hex) && hex.Length == 64)
        {
            _cachedPrivKey = Convert.FromHexString(hex);
            return _cachedPrivKey;
        }

        var (priv, _) = NostrCrypto.GenerateKeyPair();
        await SecureStorage.Default.SetAsync(PrivKeyStorageKey, Convert.ToHexStringLower(priv));
        _cachedPrivKey = priv;
        return priv;
    }

    public async Task<string> GetNpubAsync()
    {
        byte[] priv = await GetOrCreatePrivateKeyAsync();
        byte[] pub = NostrCrypto.GetXOnlyPubKey(priv);
        return Bech32.EncodeNpub(pub);
    }
}
