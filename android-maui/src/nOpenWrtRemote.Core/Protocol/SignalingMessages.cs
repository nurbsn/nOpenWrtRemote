using System.Text.Json.Serialization;

namespace nOpenWrtRemote.Core.Protocol;

public static class NortConstants
{
    public const int KindRequest = 24135;
    public const int KindResponse = 24136;
    public const string DefaultRelay = "wss://relay.gfmm.eu";
}

public sealed class PairRequestMessage
{
    [JsonPropertyName("type")] public string Type { get; set; } = "pair_request";
    [JsonPropertyName("v")] public int V { get; set; } = 1;
    [JsonPropertyName("req_id")] public string ReqId { get; set; } = string.Empty;
    [JsonPropertyName("ts")] public long Ts { get; set; }
    [JsonPropertyName("secret")] public string Secret { get; set; } = string.Empty;
    [JsonPropertyName("device_name")] public string DeviceName { get; set; } = string.Empty;
}

public sealed class PairAckMessage
{
    [JsonPropertyName("type")] public string Type { get; set; } = string.Empty;
    [JsonPropertyName("v")] public int V { get; set; }
    [JsonPropertyName("req_id")] public string ReqId { get; set; } = string.Empty;
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("router_name")] public string? RouterName { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class TunnelOpenMessage
{
    [JsonPropertyName("type")] public string Type { get; set; } = "tunnel_open";
    [JsonPropertyName("v")] public int V { get; set; } = 1;
    [JsonPropertyName("req_id")] public string ReqId { get; set; } = string.Empty;
    [JsonPropertyName("ts")] public long Ts { get; set; }
    [JsonPropertyName("session_id")] public string SessionId { get; set; } = string.Empty;
    [JsonPropertyName("relay_tunnel_url")] public string RelayTunnelUrl { get; set; } = string.Empty;
    [JsonPropertyName("router_token")] public string RouterToken { get; set; } = string.Empty;
    [JsonPropertyName("client_eph_pub")] public string ClientEphPub { get; set; } = string.Empty;
}

public sealed class TunnelAckMessage
{
    [JsonPropertyName("type")] public string Type { get; set; } = string.Empty;
    [JsonPropertyName("v")] public int V { get; set; }
    [JsonPropertyName("req_id")] public string ReqId { get; set; } = string.Empty;
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("session_id")] public string? SessionId { get; set; }
    [JsonPropertyName("router_eph_pub")] public string? RouterEphPub { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
}
