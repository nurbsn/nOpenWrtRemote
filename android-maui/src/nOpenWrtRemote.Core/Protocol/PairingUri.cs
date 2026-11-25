using nOpenWrtRemote.Core.Crypto;

namespace nOpenWrtRemote.Core.Protocol;

public sealed record PairingUri(
    int Version,
    string RouterNpub,
    byte[] RouterPubKey32,
    string RelayUrl,
    string Secret,
    string RouterName,
    string? LanIp)
{
    public string RouterPubHex => Convert.ToHexStringLower(RouterPubKey32);

    public static PairingUri Parse(string rawUri)
    {
        if (string.IsNullOrWhiteSpace(rawUri))
            throw new FormatException("Empty pairing URI.");

        if (!Uri.TryCreate(rawUri.Trim(), UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, "nopenwrt", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(uri.Host, "pair", StringComparison.OrdinalIgnoreCase))
        {
            throw new FormatException("Pairing URI must start with nopenwrt://pair.");
        }

        var query = ParseQuery(uri.Query);
        if (!query.TryGetValue("v", out string? vStr) || !int.TryParse(vStr, out int version) || version != 1)
            throw new FormatException("Unsupported pairing version.");

        if (!query.TryGetValue("npub", out string? npub) || string.IsNullOrWhiteSpace(npub))
            throw new FormatException("Missing npub parameter.");

        byte[] pub32 = Bech32.DecodeNpub(npub);

        if (!query.TryGetValue("relay", out string? relay) || !IsValidRelayUrl(relay))
            throw new FormatException("Invalid or missing relay URL.");

        if (!query.TryGetValue("secret", out string? secret) || secret.Length < 16)
            throw new FormatException("Invalid or missing pairing secret.");

        string name = query.TryGetValue("name", out string? n) && !string.IsNullOrWhiteSpace(n)
            ? n.Trim()
            : "OpenWrt";

        query.TryGetValue("lan", out string? lan);
        return new PairingUri(version, npub.Trim().ToLowerInvariant(), pub32, relay.Trim(), secret.Trim(), name, lan);
    }

    public static bool IsValidRelayUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url.Trim(), UriKind.Absolute, out var u))
            return false;

        if (string.Equals(u.Scheme, "wss", StringComparison.OrdinalIgnoreCase))
            return true;

        return string.Equals(u.Scheme, "ws", StringComparison.OrdinalIgnoreCase) &&
               (string.Equals(u.Host, "127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(u.Host, "localhost", StringComparison.OrdinalIgnoreCase));
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(query))
            return result;

        string trimmed = query.StartsWith('?') ? query[1..] : query;
        foreach (string part in trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = part.IndexOf('=');
            if (eq <= 0) continue;
            string key = Uri.UnescapeDataString(part[..eq].Replace('+', ' '));
            string val = Uri.UnescapeDataString(part[(eq + 1)..].Replace('+', ' '));
            result[key] = val;
        }
        return result;
    }
}
