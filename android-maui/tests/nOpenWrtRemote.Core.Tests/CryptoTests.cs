using System.Security.Cryptography;
using System.Text;
using nOpenWrtRemote.Core.Crypto;
using nOpenWrtRemote.Core.Protocol;
using Xunit;

namespace nOpenWrtRemote.Core.Tests;

public sealed class CryptoTests
{
    [Fact]
    public void ChaCha20_Matches_Rfc8439_Vector()
    {
        byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] nonce = Convert.FromHexString("000000000000004a00000000");
        byte[] plaintext = Encoding.ASCII.GetBytes(
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
        byte[] expected = Convert.FromHexString(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d");

        byte[] actual = ChaCha20.Transform(key, nonce, 1u, plaintext);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(1, 32)]
    [InlineData(32, 32)]
    [InlineData(33, 64)]
    [InlineData(256, 256)]
    [InlineData(257, 320)]
    [InlineData(513, 640)]
    [InlineData(10000, 10240)]
    [InlineData(65535, 65536)]
    public void Nip44_CalcPaddedLen_MatchesSpec(int unpadded, int expected)
    {
        Assert.Equal(expected, Nip44.CalcPaddedLen(unpadded));
    }

    [Fact]
    public void Nip44_EncryptDecrypt_RoundTrip_And_TamperDetection()
    {
        var (skA, pkA) = NostrCrypto.GenerateKeyPair();
        var (skB, pkB) = NostrCrypto.GenerateKeyPair();

        byte[] convAB = Nip44.GetConversationKey(skA, pkB);
        byte[] convBA = Nip44.GetConversationKey(skB, pkA);
        Assert.Equal(convAB, convBA);

        const string secret = "{\"type\":\"tunnel_open\",\"session_id\":\"abcdef\"}";
        string encrypted = Nip44.Encrypt(secret, convAB);
        string decrypted = Nip44.Decrypt(encrypted, convBA);
        Assert.Equal(secret, decrypted);

        byte[] raw = Convert.FromBase64String(encrypted);
        raw[^1] ^= 0xFF;
        string tampered = Convert.ToBase64String(raw);
        Assert.Throws<CryptographicException>(() => Nip44.Decrypt(tampered, convBA));

        var (skC, _) = NostrCrypto.GenerateKeyPair();
        byte[] wrongConv = Nip44.GetConversationKey(skC, pkA);
        Assert.Throws<CryptographicException>(() => Nip44.Decrypt(encrypted, wrongConv));
    }

    [Fact]
    public void NostrEvent_SchnorrSignAndVerify()
    {
        var (sk, _) = NostrCrypto.GenerateKeyPair();
        var evt = NostrEvent.CreateSigned(sk, 24135, [["p", new string('a', 64)]], "hello+nostr/==");
        Assert.True(evt.Verify());

        evt.Content = "tampered";
        Assert.False(evt.Verify());
    }

    [Fact]
    public void Bech32_NpubNsec_RoundTrip()
    {
        var (sk, pk) = NostrCrypto.GenerateKeyPair();
        string npub = Bech32.EncodeNpub(pk);
        string nsec = Bech32.EncodeNsec(sk);

        Assert.StartsWith("npub1", npub);
        Assert.StartsWith("nsec1", nsec);
        Assert.Equal(pk, Bech32.DecodeNpub(npub));
        Assert.Equal(sk, Bech32.DecodeNsec(nsec));

        string bad = npub[..^1] + (npub[^1] == 'q' ? 'p' : 'q');
        Assert.Throws<FormatException>(() => Bech32.DecodeNpub(bad));
    }

    [Fact]
    public void TunnelCrypto_PFS_And_AntiReplay()
    {
        var (_, cId) = NostrCrypto.GenerateKeyPair();
        var (_, rId) = NostrCrypto.GenerateKeyPair();
        var (cEphPriv, cEphPub) = NostrCrypto.GenerateKeyPair();
        var (rEphPriv, rEphPub) = NostrCrypto.GenerateKeyPair();
        const string sid = "0123456789abcdef0123456789abcdef";

        using var client = new TunnelCrypto(false, cEphPriv, rEphPub, cId, rId, sid, cEphPub, rEphPub);
        using var router = new TunnelCrypto(true, rEphPriv, cEphPub, cId, rId, sid, cEphPub, rEphPub);

        byte[] env1 = client.Seal("frame-1"u8);
        byte[] env2 = client.Seal("frame-2"u8);

        Assert.Equal("frame-1"u8.ToArray(), router.Open(env1));
        Assert.Equal("frame-2"u8.ToArray(), router.Open(env2));

        // Replay must fail
        Assert.Throws<CryptographicException>(() => router.Open(env1));

        // Reverse direction works independently
        byte[] rEnv = router.Seal("router-ok"u8);
        Assert.Equal("router-ok"u8.ToArray(), client.Open(rEnv));

        // Tampered tag/ciphertext on a fresh frame fails authentication
        byte[] rEnv2 = router.Seal("router-tamper"u8);
        rEnv2[^5] ^= 0x01;
        Assert.Throws<AuthenticationTagMismatchException>(() => client.Open(rEnv2));
    }
}
