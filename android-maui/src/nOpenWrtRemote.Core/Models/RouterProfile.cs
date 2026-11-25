namespace nOpenWrtRemote.Core.Models;

public sealed class RouterProfile
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "OpenWrt";
    public string RouterNpub { get; set; } = string.Empty;
    public string RouterPubHex { get; set; } = string.Empty;
    public List<string> Relays { get; set; } = ["wss://relay.gfmm.eu"];
    public string? LanIp { get; set; }
    public DateTimeOffset PairedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastConnectedAt { get; set; }
}
