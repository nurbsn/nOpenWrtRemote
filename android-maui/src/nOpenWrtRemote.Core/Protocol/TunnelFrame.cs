using System.Buffers.Binary;
using System.Text.Json.Serialization;

namespace nOpenWrtRemote.Core.Protocol;

public enum FrameType : byte
{
    HttpReqMeta = 0x01,
    HttpReqBody = 0x02,
    HttpReqEnd = 0x03,
    HttpResMeta = 0x11,
    HttpResBody = 0x12,
    HttpResEnd = 0x13,
    HttpRst = 0x14,
    UbusReq = 0x20,
    UbusRes = 0x21,
    Ping = 0x30,
    Pong = 0x31
}

public readonly record struct TunnelFrame(FrameType Type, uint StreamId, byte[] Payload)
{
    public byte[] Encode()
    {
        byte[] buf = new byte[9 + Payload.Length];
        buf[0] = (byte)Type;
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(1, 4), StreamId);
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(5, 4), (uint)Payload.Length);
        Payload.CopyTo(buf, 9);
        return buf;
    }

    public static TunnelFrame Decode(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < 9)
            throw new FormatException("Tunnel frame shorter than 9-byte header.");

        var type = (FrameType)raw[0];
        uint streamId = BinaryPrimitives.ReadUInt32BigEndian(raw.Slice(1, 4));
        int length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(raw.Slice(5, 4)));

        if (raw.Length != 9 + length)
            throw new FormatException($"Tunnel frame length mismatch: expected {9 + length}, got {raw.Length}.");

        return new TunnelFrame(type, streamId, raw.Slice(9, length).ToArray());
    }
}

public sealed class HttpRequestMeta
{
    [JsonPropertyName("method")] public string Method { get; set; } = "GET";
    [JsonPropertyName("path")] public string Path { get; set; } = "/";
    [JsonPropertyName("headers")] public Dictionary<string, string[]> Headers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class HttpResponseMeta
{
    [JsonPropertyName("status")] public int Status { get; set; } = 200;
    [JsonPropertyName("headers")] public Dictionary<string, string[]> Headers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed record HttpProxyRequest(
    string Method,
    string Path,
    Dictionary<string, string[]> Headers,
    byte[] Body);

public sealed record HttpProxyResponse(
    int StatusCode,
    Dictionary<string, string[]> Headers,
    byte[] Body);

public interface ITunnelHttpTransport
{
    Task<HttpProxyResponse> SendHttpAsync(HttpProxyRequest request, CancellationToken ct = default);
}
