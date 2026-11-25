using System.Text;
using System.Text.Json;

namespace nOpenWrtRemote.Core.Network;

public sealed class RouterTelemetrySnapshot
{
    public string Hostname { get; set; } = "OpenWrt";
    public string Model { get; set; } = "-";
    public string OpenWrtRelease { get; set; } = "-";
    public string Kernel { get; set; } = "-";
    public long UptimeSeconds { get; set; }
    public double Load1Min { get; set; }
    public double Load5Min { get; set; }
    public long TotalRamMb { get; set; }
    public long FreeRamMb { get; set; }
    public double RamUsedPercent => TotalRamMb > 0 ? Math.Round((double)(TotalRamMb - FreeRamMb) * 100.0 / TotalRamMb, 1) : 0;
    public string WanIp { get; set; } = "-";
    public bool WanUp { get; set; }
    public int ConnectedDevicesCount { get; set; }
    public int LatencyMs { get; set; }
}

public static class UbusClient
{
    private const string AnonymousSid = "00000000000000000000000000000000";

    public static async Task<string> LoginAsync(
        TunnelSession session,
        string username,
        string password,
        CancellationToken ct = default)
    {
        var payload = new object[]
        {
            new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "call",
                @params = new object[] { AnonymousSid, "session", "login", new { username, password } }
            }
        };
        byte[] raw = await session.SendUbusRawAsync(JsonSerializer.SerializeToUtf8Bytes(payload), ct);
        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement[0];
        var result = root.GetProperty("result");
        int code = result[0].GetInt32();
        if (code != 0)
            throw new UnauthorizedAccessException($"ubus session.login failed with code {code}");

        return result[1].GetProperty("ubus_rpc_session").GetString()
               ?? throw new InvalidOperationException("Missing ubus_rpc_session");
    }

    public static async Task<RouterTelemetrySnapshot> FetchTelemetryAsync(
        TunnelSession session,
        string? ubusSessionId = null,
        CancellationToken ct = default)
    {
        string sid = string.IsNullOrWhiteSpace(ubusSessionId) ? AnonymousSid : ubusSessionId;
        var batch = new object[]
        {
            new { jsonrpc = "2.0", id = 1, method = "call", @params = new object[] { sid, "system", "board", new { } } },
            new { jsonrpc = "2.0", id = 2, method = "call", @params = new object[] { sid, "system", "info", new { } } },
            new { jsonrpc = "2.0", id = 3, method = "call", @params = new object[] { sid, "network.interface.wan", "status", new { } } },
            new { jsonrpc = "2.0", id = 4, method = "call", @params = new object[] { sid, "luci-rpc", "getHostHints", new { } } }
        };

        byte[] raw = await session.SendUbusRawAsync(JsonSerializer.SerializeToUtf8Bytes(batch), ct);
        using var doc = JsonDocument.Parse(raw);

        var snap = new RouterTelemetrySnapshot { LatencyMs = session.LatencyMs };
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
            return snap;

        foreach (var item in doc.RootElement.EnumerateArray())
        {
            int id = item.TryGetProperty("id", out var idEl) ? idEl.GetInt32() : 0;
            if (!item.TryGetProperty("result", out var res) || res.GetArrayLength() < 2 || res[0].GetInt32() != 0)
                continue;

            var body = res[1];
            switch (id)
            {
                case 1:
                    snap.Hostname = body.TryGetProperty("hostname", out var hn) ? hn.GetString() ?? "OpenWrt" : "OpenWrt";
                    snap.Model = body.TryGetProperty("model", out var md) ? md.GetString() ?? "-" : "-";
                    snap.Kernel = body.TryGetProperty("kernel", out var kn) ? kn.GetString() ?? "-" : "-";
                    if (body.TryGetProperty("release", out var rel) && rel.TryGetProperty("description", out var desc))
                        snap.OpenWrtRelease = desc.GetString() ?? "-";
                    break;

                case 2:
                    snap.UptimeSeconds = body.TryGetProperty("uptime", out var up) ? up.GetInt64() : 0;
                    if (body.TryGetProperty("load", out var ld) && ld.GetArrayLength() >= 2)
                    {
                        snap.Load1Min = Math.Round(ld[0].GetDouble() / 65536.0, 2);
                        snap.Load5Min = Math.Round(ld[1].GetDouble() / 65536.0, 2);
                    }
                    if (body.TryGetProperty("memory", out var mem))
                    {
                        long total = mem.TryGetProperty("total", out var t) ? t.GetInt64() : 0;
                        long free = mem.TryGetProperty("free", out var f) ? f.GetInt64() : 0;
                        snap.TotalRamMb = total / (1024 * 1024);
                        snap.FreeRamMb = free / (1024 * 1024);
                    }
                    break;

                case 3:
                    snap.WanUp = body.TryGetProperty("up", out var wanUp) && wanUp.GetBoolean();
                    if (body.TryGetProperty("ipv4-address", out var ips) && ips.GetArrayLength() > 0 &&
                        ips[0].TryGetProperty("address", out var addr))
                    {
                        snap.WanIp = addr.GetString() ?? "-";
                    }
                    break;

                case 4:
                    if (body.ValueKind == JsonValueKind.Object)
                        snap.ConnectedDevicesCount = body.EnumerateObject().Count();
                    break;
            }
        }

        return snap;
    }

    public static async Task RebootAsync(TunnelSession session, string ubusSessionId, CancellationToken ct = default)
    {
        var payload = new object[]
        {
            new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "call",
                @params = new object[] { ubusSessionId, "system", "reboot", new { } }
            }
        };
        await session.SendUbusRawAsync(JsonSerializer.SerializeToUtf8Bytes(payload), ct);
    }
}
