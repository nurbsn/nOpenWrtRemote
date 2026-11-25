using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using nOpenWrtRemote.Core.Crypto;

namespace nOpenWrtRemote.Core.Protocol;

public sealed class NostrEvent
{
    public static readonly JsonSerializerOptions CanonicalJsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("pubkey")]
    public string PubKey { get; set; } = string.Empty;

    [JsonPropertyName("created_at")]
    public long CreatedAt { get; set; }

    [JsonPropertyName("kind")]
    public int Kind { get; set; }

    [JsonPropertyName("tags")]
    public List<List<string>> Tags { get; set; } = [];

    [JsonPropertyName("content")]
    public string Content { get; set; } = string.Empty;

    [JsonPropertyName("sig")]
    public string Sig { get; set; } = string.Empty;

    public static string ComputeIdHex(string pubKeyHex, long createdAt, int kind, List<List<string>> tags, string content)
    {
        object[] payload = [0, pubKeyHex, createdAt, kind, tags, content];
        string canonical = JsonSerializer.Serialize(payload, CanonicalJsonOptions);
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexStringLower(hash);
    }

    public static NostrEvent CreateSigned(
        ReadOnlySpan<byte> privKey32,
        int kind,
        List<List<string>> tags,
        string content,
        long? createdAt = null)
    {
        byte[] pubKey = NostrCrypto.GetXOnlyPubKey(privKey32);
        string pubHex = Convert.ToHexStringLower(pubKey);
        long ts = createdAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string idHex = ComputeIdHex(pubHex, ts, kind, tags, content);
        byte[] sig = NostrCrypto.SignBip340(Convert.FromHexString(idHex), privKey32);

        return new NostrEvent
        {
            Id = idHex,
            PubKey = pubHex,
            CreatedAt = ts,
            Kind = kind,
            Tags = tags,
            Content = content,
            Sig = Convert.ToHexStringLower(sig)
        };
    }

    public bool Verify()
    {
        if (PubKey.Length != 64 || Id.Length != 64 || Sig.Length != 128)
            return false;

        string expectedId = ComputeIdHex(PubKey, CreatedAt, Kind, Tags, Content);
        if (!string.Equals(expectedId, Id, StringComparison.Ordinal))
            return false;

        try
        {
            return NostrCrypto.VerifyBip340(
                Convert.FromHexString(Id),
                Convert.FromHexString(Sig),
                Convert.FromHexString(PubKey));
        }
        catch
        {
            return false;
        }
    }
}
