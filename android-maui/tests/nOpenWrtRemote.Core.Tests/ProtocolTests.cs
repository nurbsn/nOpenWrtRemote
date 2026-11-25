using nOpenWrtRemote.Core.Crypto;
using nOpenWrtRemote.Core.Protocol;
using Xunit;

namespace nOpenWrtRemote.Core.Tests;

public sealed class ProtocolTests
{
    [Fact]
    public void PairingUri_ParsesValidUri()
    {
        var (_, pk) = NostrCrypto.GenerateKeyPair();
        string npub = Bech32.EncodeNpub(pk);
        string raw = $"nopenwrt://pair?v=1&npub={npub}&relay=wss%3A%2F%2Frelay.gfmm.eu&secret=0123456789abcdef0123456789abcdef&name=Domowy%20Router&lan=192.168.1.1";

        var parsed = PairingUri.Parse(raw);
        Assert.Equal(1, parsed.Version);
        Assert.Equal(npub, parsed.RouterNpub);
        Assert.Equal("wss://relay.gfmm.eu", parsed.RelayUrl);
        Assert.Equal("Domowy Router", parsed.RouterName);
        Assert.Equal("192.168.1.1", parsed.LanIp);
    }

    [Fact]
    public void PairingUri_RejectsPlaintextWsNonLocalhost()
    {
        var (_, pk) = NostrCrypto.GenerateKeyPair();
        string npub = Bech32.EncodeNpub(pk);
        string raw = $"nopenwrt://pair?v=1&npub={npub}&relay=ws%3A%2F%2Fevil.example.com&secret=0123456789abcdef0123456789abcdef";
        Assert.Throws<FormatException>(() => PairingUri.Parse(raw));
    }

    [Fact]
    public void TunnelFrame_EncodeDecode_RoundTrip()
    {
        var original = new TunnelFrame(FrameType.HttpReqMeta, 42u, "{\"method\":\"GET\"}"u8.ToArray());
        byte[] encoded = original.Encode();
        var decoded = TunnelFrame.Decode(encoded);
        Assert.Equal(original.Type, decoded.Type);
        Assert.Equal(original.StreamId, decoded.StreamId);
        Assert.Equal(original.Payload, decoded.Payload);
    }
}
