using System.Text;

namespace nOpenWrtRemote.Core.Crypto;

public static class Bech32
{
    private const string Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    private static readonly uint[] Generators =
    [
        0x3b6a57b2u,
        0x26508e6du,
        0x1ea119fau,
        0x3d4233ddu,
        0x2a1462b3u
    ];

    public static string EncodeNpub(ReadOnlySpan<byte> pubKey32)
    {
        if (pubKey32.Length != 32)
            throw new ArgumentException("Public key must be 32 bytes.", nameof(pubKey32));
        return Encode("npub", pubKey32);
    }

    public static string EncodeNsec(ReadOnlySpan<byte> privKey32)
    {
        if (privKey32.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes.", nameof(privKey32));
        return Encode("nsec", privKey32);
    }

    public static byte[] DecodeNpub(string npub)
    {
        var (hrp, data) = Decode(npub);
        if (hrp != "npub" || data.Length != 32)
            throw new FormatException("Invalid npub.");
        return data;
    }

    public static byte[] DecodeNsec(string nsec)
    {
        var (hrp, data) = Decode(nsec);
        if (hrp != "nsec" || data.Length != 32)
            throw new FormatException("Invalid nsec.");
        return data;
    }

    public static string Encode(string hrp, ReadOnlySpan<byte> data)
    {
        var conv = ConvertBits(data, 8, 5, pad: true);
        var values = new List<byte>(hrp.Length * 2 + 1 + conv.Length + 6);
        values.AddRange(HrpExpand(hrp));
        values.AddRange(conv);
        for (int i = 0; i < 6; i++) values.Add(0);

        uint polymod = Polymod(values) ^ 1u;

        var sb = new StringBuilder(hrp.Length + 1 + conv.Length + 6);
        sb.Append(hrp);
        sb.Append('1');
        foreach (byte b in conv)
            sb.Append(Charset[b]);
        for (int i = 0; i < 6; i++)
            sb.Append(Charset[(int)((polymod >> (5 * (5 - i))) & 31)]);
        return sb.ToString();
    }

    public static (string Hrp, byte[] Data) Decode(string bech)
    {
        if (string.IsNullOrWhiteSpace(bech))
            throw new FormatException("Empty Bech32 string.");

        string normalized = bech.Trim().ToLowerInvariant();
        int pos = normalized.LastIndexOf('1');
        if (pos < 1 || pos + 7 > normalized.Length)
            throw new FormatException("Invalid Bech32 separator.");

        string hrp = normalized[..pos];
        var data = new byte[normalized.Length - pos - 1];
        for (int i = 0; i < data.Length; i++)
        {
            int idx = Charset.IndexOf(normalized[pos + 1 + i]);
            if (idx < 0)
                throw new FormatException("Invalid Bech32 character.");
            data[i] = (byte)idx;
        }

        var check = new List<byte>(hrp.Length * 2 + 1 + data.Length);
        check.AddRange(HrpExpand(hrp));
        check.AddRange(data);
        if (Polymod(check) != 1u)
            throw new FormatException("Invalid Bech32 checksum.");

        byte[] payload = ConvertBits(data.AsSpan(0, data.Length - 6), 5, 8, pad: false);
        return (hrp, payload);
    }

    private static uint Polymod(IReadOnlyList<byte> values)
    {
        uint chk = 1;
        for (int i = 0; i < values.Count; i++)
        {
            uint top = chk >> 25;
            chk = ((chk & 0x1ffffffu) << 5) ^ values[i];
            for (int j = 0; j < 5; j++)
            {
                if (((top >> j) & 1u) != 0)
                    chk ^= Generators[j];
            }
        }
        return chk;
    }

    private static byte[] HrpExpand(string hrp)
    {
        var ret = new byte[hrp.Length * 2 + 1];
        for (int i = 0; i < hrp.Length; i++)
            ret[i] = (byte)(hrp[i] >> 5);
        ret[hrp.Length] = 0;
        for (int i = 0; i < hrp.Length; i++)
            ret[hrp.Length + 1 + i] = (byte)(hrp[i] & 31);
        return ret;
    }

    private static byte[] ConvertBits(ReadOnlySpan<byte> data, int fromBits, int toBits, bool pad)
    {
        int acc = 0;
        int bits = 0;
        int maxv = (1 << toBits) - 1;
        var ret = new List<byte>((data.Length * fromBits + toBits - 1) / toBits);

        foreach (byte value in data)
        {
            acc = (acc << fromBits) | value;
            bits += fromBits;
            while (bits >= toBits)
            {
                bits -= toBits;
                ret.Add((byte)((acc >> bits) & maxv));
            }
        }

        if (pad)
        {
            if (bits > 0)
                ret.Add((byte)((acc << (toBits - bits)) & maxv));
        }
        else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0)
        {
            throw new FormatException("Invalid Bech32 padding bits.");
        }

        return ret.ToArray();
    }
}
