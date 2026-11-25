using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using nOpenWrtRemote.Core.Crypto;
using nOpenWrtRemote.Core.Network;
using nOpenWrtRemote.Core.Protocol;

namespace nOpenWrtRemote.MockRouter;

public static class Program
{
    public static async Task Main(string[] args)
    {
        string relayUrl = "ws://127.0.0.1:8787";
        string routerName = "Mock-OpenWrt-AX6000";
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--relay") relayUrl = args[i + 1];
            if (args[i] == "--name") routerName = args[i + 1];
        }

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        await using var mockLuci = new MockLuciBackend();
        mockLuci.Start();

        var (privKey, pubKey) = NostrCrypto.GenerateKeyPair();
        string npub = Bech32.EncodeNpub(pubKey);
        string pubHex = Convert.ToHexStringLower(pubKey);
        string secret = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));

        string pairUri = $"nopenwrt://pair?v=1&npub={npub}&relay={Uri.EscapeDataString(relayUrl)}&secret={secret}&name={Uri.EscapeDataString(routerName)}&lan=192.168.1.1";

        Console.WriteLine("=== nOpenWrtRemote MockRouter ===");
        Console.WriteLine($"Router npub : {npub}");
        Console.WriteLine($"Mock LuCI   : http://127.0.0.1:{mockLuci.Port}");
        Console.WriteLine($"Nostr Relay : {relayUrl}");
        Console.WriteLine();
        Console.WriteLine("Wklej poniższy link parowania w aplikacji Android:");
        Console.WriteLine(pairUri);
        Console.WriteLine();

        var authorizedPeers = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        while (!cts.IsCancellationRequested)
        {
            try
            {
                await using var relay = new NostrRelayClient();
                await relay.ConnectAsync(relayUrl, cts.Token);
                await relay.SubscribeAsync("mock-router", [NortConstants.KindRequest], [pubHex], cts.Token);
                Console.WriteLine("[nostr] Połączono z przekaźnikiem. Oczekiwanie na zdarzenia...");

                await foreach (var evt in relay.Events.ReadAllAsync(cts.Token))
                {
                    if (evt.Kind != NortConstants.KindRequest) continue;
                    byte[] peerPub = Convert.FromHexString(evt.PubKey);
                    byte[] convKey = Nip44.GetConversationKey(privKey, peerPub);
                    string plain = Nip44.Decrypt(evt.Content, convKey);
                    using var doc = JsonDocument.Parse(plain);
                    string type = doc.RootElement.GetProperty("type").GetString() ?? "";
                    string reqId = doc.RootElement.GetProperty("req_id").GetString() ?? "";

                    if (type == "pair_request")
                    {
                        string reqSecret = doc.RootElement.GetProperty("secret").GetString() ?? "";
                        string devName = doc.RootElement.TryGetProperty("device_name", out var dn) ? dn.GetString() ?? "Android" : "Android";
                        bool ok = CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(reqSecret), Encoding.UTF8.GetBytes(secret));
                        if (ok) authorizedPeers[evt.PubKey] = devName;

                        var ack = new PairAckMessage
                        {
                            Type = "pair_ack",
                            V = 1,
                            ReqId = reqId,
                            Ok = ok,
                            RouterName = routerName,
                            Error = ok ? null : "invalid pairing secret"
                        };
                        string enc = Nip44.Encrypt(JsonSerializer.Serialize(ack), convKey);
                        var resp = NostrEvent.CreateSigned(privKey, NortConstants.KindResponse, [["p", evt.PubKey], ["e", evt.Id]], enc);
                        await relay.PublishEventAsync(resp, cts.Token);
                        Console.WriteLine($"[pair] device={devName} ok={ok}");
                    }
                    else if (type == "tunnel_open")
                    {
                        string sessionId = doc.RootElement.GetProperty("session_id").GetString() ?? "";
                        string tunnelBase = doc.RootElement.GetProperty("relay_tunnel_url").GetString() ?? "";
                        string routerToken = doc.RootElement.GetProperty("router_token").GetString() ?? "";
                        string clientEphHex = doc.RootElement.GetProperty("client_eph_pub").GetString() ?? "";

                        if (!authorizedPeers.ContainsKey(evt.PubKey))
                        {
                            var deny = new TunnelAckMessage { Type = "tunnel_ack", V = 1, ReqId = reqId, Ok = false, SessionId = sessionId, Error = "peer not paired" };
                            string encDeny = Nip44.Encrypt(JsonSerializer.Serialize(deny), convKey);
                            await relay.PublishEventAsync(NostrEvent.CreateSigned(privKey, NortConstants.KindResponse, [["p", evt.PubKey], ["e", evt.Id]], encDeny), cts.Token);
                            continue;
                        }

                        var (rEphPriv, rEphPub) = NostrCrypto.GenerateKeyPair();
                        byte[] clientEphPub = Convert.FromHexString(clientEphHex);
                        var tc = new TunnelCrypto(true, rEphPriv, clientEphPub, peerPub, pubKey, sessionId, clientEphPub, rEphPub);

                        var ack = new TunnelAckMessage
                        {
                            Type = "tunnel_ack",
                            V = 1,
                            ReqId = reqId,
                            Ok = true,
                            SessionId = sessionId,
                            RouterEphPub = Convert.ToHexStringLower(rEphPub)
                        };
                        string enc = Nip44.Encrypt(JsonSerializer.Serialize(ack), convKey);
                        await relay.PublishEventAsync(NostrEvent.CreateSigned(privKey, NortConstants.KindResponse, [["p", evt.PubKey], ["e", evt.Id]], enc), cts.Token);

                        string wsUrl = $"{tunnelBase}?role=router&token={routerToken}";
                        _ = Task.Run(() => ServeTunnelAsync(wsUrl, tc, mockLuci.Port, cts.Token), cts.Token);
                        Console.WriteLine($"[tunnel] Sesja otwarta: {sessionId}");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[warn] {ex.Message}; ponawiam za 3s...");
                await Task.Delay(3000, cts.Token);
            }
        }
    }

    private static async Task ServeTunnelAsync(string wsUrl, TunnelCrypto tc, int luciPort, CancellationToken ct)
    {
        using var ws = new ClientWebSocket();
        await ws.ConnectAsync(new Uri(wsUrl), ct);
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var txLock = new SemaphoreSlim(1, 1);
        var pending = new ConcurrentDictionary<uint, (HttpRequestMeta Meta, MemoryStream Body)>();

        async Task SendFrame(TunnelFrame f)
        {
            byte[] env = tc.Seal(f.Encode());
            await txLock.WaitAsync(ct);
            try { await ws.SendAsync(env, WebSocketMessageType.Binary, true, ct); }
            finally { txLock.Release(); }
        }

        byte[] buf = new byte[64 * 1024];
        using var ms = new MemoryStream();
        while (!ct.IsCancellationRequested && ws.State == WebSocketState.Open)
        {
            ms.SetLength(0);
            WebSocketReceiveResult res;
            do
            {
                res = await ws.ReceiveAsync(buf, ct);
                if (res.MessageType == WebSocketMessageType.Close) return;
                ms.Write(buf, 0, res.Count);
            } while (!res.EndOfMessage);

            var frame = TunnelFrame.Decode(tc.Open(ms.GetBuffer().AsSpan(0, (int)ms.Length)));
            switch (frame.Type)
            {
                case FrameType.Ping:
                    await SendFrame(new TunnelFrame(FrameType.Pong, 0, frame.Payload));
                    break;

                case FrameType.UbusReq:
                {
                    var req = new HttpRequestMessage(HttpMethod.Post, $"http://127.0.0.1:{luciPort}/ubus")
                    {
                        Content = new ByteArrayContent(frame.Payload)
                    };
                    var resp = await http.SendAsync(req, ct);
                    byte[] body = await resp.Content.ReadAsByteArrayAsync(ct);
                    await SendFrame(new TunnelFrame(FrameType.UbusRes, frame.StreamId, body));
                    break;
                }

                case FrameType.HttpReqMeta:
                    pending[frame.StreamId] = (JsonSerializer.Deserialize<HttpRequestMeta>(frame.Payload)!, new MemoryStream());
                    break;

                case FrameType.HttpReqBody:
                    if (pending.TryGetValue(frame.StreamId, out var p)) p.Body.Write(frame.Payload);
                    break;

                case FrameType.HttpReqEnd:
                    if (pending.TryRemove(frame.StreamId, out var done))
                    {
                        var hReq = new HttpRequestMessage(new HttpMethod(done.Meta.Method), $"http://127.0.0.1:{luciPort}{done.Meta.Path}");
                        if (done.Body.Length > 0)
                            hReq.Content = new ByteArrayContent(done.Body.ToArray());
                        foreach (var (k, vals) in done.Meta.Headers)
                        {
                            if (!k.Equals("Host", StringComparison.OrdinalIgnoreCase) && !k.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                                hReq.Headers.TryAddWithoutValidation(k, vals);
                        }
                        var hResp = await http.SendAsync(hReq, ct);
                        var resHeaders = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
                        foreach (var h in hResp.Headers) resHeaders[h.Key] = h.Value.ToArray();
                        foreach (var h in hResp.Content.Headers) resHeaders[h.Key] = h.Value.ToArray();
                        byte[] body = await hResp.Content.ReadAsByteArrayAsync(ct);

                        await SendFrame(new TunnelFrame(FrameType.HttpResMeta, frame.StreamId,
                            JsonSerializer.SerializeToUtf8Bytes(new HttpResponseMeta { Status = (int)hResp.StatusCode, Headers = resHeaders })));
                        await SendFrame(new TunnelFrame(FrameType.HttpResBody, frame.StreamId, body));
                        await SendFrame(new TunnelFrame(FrameType.HttpResEnd, frame.StreamId, []));
                    }
                    break;
            }
        }
    }
}

public sealed class MockLuciBackend : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;
    public int Port { get; private set; }

    public void Start()
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _loop = Task.Run(() => LoopAsync(_cts.Token));
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(ct);
                _ = Task.Run(() => HandleAsync(client, ct), ct);
            }
        }
        catch { }
    }

    private static async Task HandleAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            await using var stream = client.GetStream();
            byte[] buf = new byte[8192];
            int n = await stream.ReadAsync(buf, ct);
            if (n <= 0) return;

            string reqText = Encoding.UTF8.GetString(buf, 0, n);
            string firstLine = reqText.Split("\r\n")[0];
            string path = firstLine.Split(' ')[1];

            byte[] body;
            string contentType = "text/html; charset=utf-8";
            string extraHeaders = "Set-Cookie: sysauth_http=mocktoken123; path=/cgi-bin/luci/; HttpOnly; Secure\r\n";

            if (path.StartsWith("/luci-static/", StringComparison.Ordinal))
            {
                contentType = "application/javascript";
                body = Encoding.UTF8.GetBytes("console.log('OpenWrt Mock LuCI static asset loaded');");
            }
            else if (path.StartsWith("/ubus", StringComparison.Ordinal))
            {
                contentType = "application/json";
                body = Encoding.UTF8.GetBytes("""
                    [
                      {"jsonrpc":"2.0","id":1,"result":[0,{"hostname":"Mock-OpenWrt-AX6000","model":"Xiaomi AX6000","kernel":"6.6.58","release":{"description":"OpenWrt 24.10.0"}}]},
                      {"jsonrpc":"2.0","id":2,"result":[0,{"uptime":123456,"load":[16384,12288,8192],"memory":{"total":536870912,"free":314572800}}]},
                      {"jsonrpc":"2.0","id":3,"result":[0,{"up":true,"ipv4-address":[{"address":"100.64.12.34"}]}]},
                      {"jsonrpc":"2.0","id":4,"result":[0,{"AA:BB:CC:DD:EE:01":{"name":"Pixel-9"},"AA:BB:CC:DD:EE:02":{"name":"Laptop"}}]}
                    ]
                    """);
            }
            else
            {
                body = Encoding.UTF8.GetBytes("<!DOCTYPE html><html><head><script src='/luci-static/resources/luci.js'></script></head><body><h1>OpenWrt LuCI Mock</h1><p>Połączono przez szyfrowany tunel E2EE NORT-1.</p></body></html>");
            }

            string resp = $"HTTP/1.1 200 OK\r\nContent-Type: {contentType}\r\n{extraHeaders}Content-Length: {body.Length}\r\nConnection: close\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(resp), ct);
            await stream.WriteAsync(body, ct);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _listener.Stop();
        if (_loop is not null) { try { await _loop; } catch { } }
        _cts.Dispose();
    }
}
