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
using Xunit;

namespace nOpenWrtRemote.Core.Tests;

public sealed class EndToEndTunnelTests
{
    [Fact]
    public async Task Full_Nostr_Pairing_E2EE_Tunnel_And_LocalLuciProxy_EndToEnd()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(25));

        await using var relay = new InProcessBlindRelay();
        relay.Start();

        await using var mockLuci = new InProcessMockLuciServer();
        mockLuci.Start();

        var (routerPriv, routerPub) = NostrCrypto.GenerateKeyPair();
        string routerNpub = Bech32.EncodeNpub(routerPub);
        const string pairSecret = "00112233445566778899aabbccddeeff";

        using var routerAgentCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
        var routerTask = RunSimulatedRouterAgentAsync(relay.WsBaseUrl, routerPriv, routerPub, pairSecret, mockLuci.Port, routerAgentCts.Token);

        // Give router agent a moment to connect & subscribe
        await Task.Delay(250, cts.Token);

        var (clientPriv, _) = NostrCrypto.GenerateKeyPair();
        string pairUriRaw = $"nopenwrt://pair?v=1&npub={routerNpub}&relay={Uri.EscapeDataString(relay.WsBaseUrl)}&secret={pairSecret}&name=TestOpenWrt";
        var pairing = PairingUri.Parse(pairUriRaw);

        // 1. Pair over Nostr NIP-44 v2
        var profile = await TunnelSession.PairAsync(clientPriv, pairing, "PixelTest", cts.Token);
        Assert.Equal("TestOpenWrt", profile.Name);

        // 2. Open E2EE PFS Tunnel
        await using var session = await TunnelSession.ConnectAsync(clientPriv, profile, cts.Token);
        Assert.True(session.IsConnected);

        // 3. Start LocalLuciProxyServer on 127.0.0.1
        await using var proxy = new LocalLuciProxyServer(session);
        proxy.Start();

        // 4. Unauthenticated request without local cookie MUST get 403 Forbidden
        var handlerNoCookies = new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false };
        using var unauthHttp = new HttpClient(handlerNoCookies);
        var unauthRes = await unauthHttp.GetAsync($"{proxy.BaseUrl}/cgi-bin/luci", cts.Token);
        Assert.Equal(HttpStatusCode.Forbidden, unauthRes.StatusCode);

        // 5. Authenticate via /__nort_auth -> HttpOnly cookie + redirect -> full LuCI HTML
        var cookieContainer = new CookieContainer();
        using var authedHttp = new HttpClient(new HttpClientHandler
        {
            CookieContainer = cookieContainer,
            AllowAutoRedirect = true
        });
        var luciRes = await authedHttp.GetAsync(proxy.EntryUrl, cts.Token);
        Assert.Equal(HttpStatusCode.OK, luciRes.StatusCode);
        string luciHtml = await luciRes.Content.ReadAsStringAsync(cts.Token);
        Assert.Contains("OpenWrt LuCI E2EE Mock", luciHtml);

        // Verify ; Secure was stripped ONLY on loopback so sysauth_http cookie is stored
        var cookies = cookieContainer.GetCookies(new Uri(proxy.BaseUrl));
        Assert.NotNull(cookies["sysauth_http"]);
        Assert.NotNull(cookies[LocalLuciProxyServer.SessionCookieName]);

        // 6. Static asset caching: 1st request misses -> hits router; 2nd request hits local cache
        string js1 = await authedHttp.GetStringAsync($"{proxy.BaseUrl}/luci-static/resources/luci.js", cts.Token);
        string js2 = await authedHttp.GetStringAsync($"{proxy.BaseUrl}/luci-static/resources/luci.js", cts.Token);
        Assert.Equal(js1, js2);
        Assert.Equal(1, mockLuci.StaticHits);
        Assert.Equal(1, proxy.CacheMisses);
        Assert.Equal(1, proxy.CacheHits);

        // 7. ubus JSON-RPC over E2EE tunnel
        var telemetry = await UbusClient.FetchTelemetryAsync(session, ct: cts.Token);
        Assert.Equal("OpenWrt-Test-Router", telemetry.Hostname);
        Assert.Equal("24.10.0", telemetry.OpenWrtRelease);
        Assert.True(telemetry.WanUp);

        // 8. Verify blind relay NEVER saw plaintext HTTP/LuCI/ubus strings inside tunnel traffic
        Assert.DoesNotContain(relay.ObservedTunnelFrames, bytes =>
        {
            string asAscii = Encoding.UTF8.GetString(bytes);
            return asAscii.Contains("OpenWrt", StringComparison.Ordinal) ||
                   asAscii.Contains("sysauth", StringComparison.Ordinal) ||
                   asAscii.Contains("/cgi-bin/luci", StringComparison.Ordinal);
        });
        Assert.NotEmpty(relay.ObservedTunnelFrames);

        routerAgentCts.Cancel();
        try { await routerTask; } catch { }
    }

    private static async Task RunSimulatedRouterAgentAsync(
        string relayWsUrl,
        byte[] routerPriv,
        byte[] routerPub,
        string pairSecret,
        int luciPort,
        CancellationToken ct)
    {
        string pubHex = Convert.ToHexStringLower(routerPub);
        var authorized = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        await using var relay = new NostrRelayClient();
        await relay.ConnectAsync(relayWsUrl, ct);
        await relay.SubscribeAsync("router-sub", [NortConstants.KindRequest], [pubHex], ct);

        await foreach (var evt in relay.Events.ReadAllAsync(ct))
        {
            if (evt.Kind != NortConstants.KindRequest) continue;
            byte[] peerPub = Convert.FromHexString(evt.PubKey);
            byte[] convKey = Nip44.GetConversationKey(routerPriv, peerPub);
            string plain = Nip44.Decrypt(evt.Content, convKey);
            using var doc = JsonDocument.Parse(plain);
            string type = doc.RootElement.GetProperty("type").GetString()!;
            string reqId = doc.RootElement.GetProperty("req_id").GetString()!;

            if (type == "pair_request")
            {
                bool ok = doc.RootElement.GetProperty("secret").GetString() == pairSecret;
                if (ok) authorized[evt.PubKey] = true;
                var ack = new PairAckMessage { Type = "pair_ack", V = 1, ReqId = reqId, Ok = ok, RouterName = "TestOpenWrt" };
                string enc = Nip44.Encrypt(JsonSerializer.Serialize(ack), convKey);
                await relay.PublishEventAsync(NostrEvent.CreateSigned(routerPriv, NortConstants.KindResponse, [["p", evt.PubKey]], enc), ct);
            }
            else if (type == "tunnel_open")
            {
                string sid = doc.RootElement.GetProperty("session_id").GetString()!;
                string baseUrl = doc.RootElement.GetProperty("relay_tunnel_url").GetString()!;
                string token = doc.RootElement.GetProperty("router_token").GetString()!;
                byte[] cEph = Convert.FromHexString(doc.RootElement.GetProperty("client_eph_pub").GetString()!);
                var (rEphPriv, rEphPub) = NostrCrypto.GenerateKeyPair();
                var tc = new TunnelCrypto(true, rEphPriv, cEph, peerPub, routerPub, sid, cEph, rEphPub);

                var ack = new TunnelAckMessage { Type = "tunnel_ack", V = 1, ReqId = reqId, Ok = true, SessionId = sid, RouterEphPub = Convert.ToHexStringLower(rEphPub) };
                string enc = Nip44.Encrypt(JsonSerializer.Serialize(ack), convKey);
                await relay.PublishEventAsync(NostrEvent.CreateSigned(routerPriv, NortConstants.KindResponse, [["p", evt.PubKey]], enc), ct);

                _ = Task.Run(async () =>
                {
                    using var ws = new ClientWebSocket();
                    await ws.ConnectAsync(new Uri($"{baseUrl}?role=router&token={token}"), ct);
                    using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
                    var streams = new ConcurrentDictionary<uint, (HttpRequestMeta Meta, MemoryStream Body)>();
                    byte[] buf = new byte[64 * 1024];
                    using var ms = new MemoryStream();
                    while (!ct.IsCancellationRequested && ws.State == WebSocketState.Open)
                    {
                        ms.SetLength(0);
                        WebSocketReceiveResult r;
                        do
                        {
                            r = await ws.ReceiveAsync(buf, ct);
                            if (r.MessageType == WebSocketMessageType.Close) return;
                            ms.Write(buf, 0, r.Count);
                        } while (!r.EndOfMessage);

                        var f = TunnelFrame.Decode(tc.Open(ms.GetBuffer().AsSpan(0, (int)ms.Length)));
                        if (f.Type == FrameType.Ping)
                        {
                            await ws.SendAsync(tc.Seal(new TunnelFrame(FrameType.Pong, 0, f.Payload).Encode()), WebSocketMessageType.Binary, true, ct);
                        }
                        else if (f.Type == FrameType.UbusReq)
                        {
                            var resp = await http.PostAsync($"http://127.0.0.1:{luciPort}/ubus", new ByteArrayContent(f.Payload), ct);
                            byte[] body = await resp.Content.ReadAsByteArrayAsync(ct);
                            await ws.SendAsync(tc.Seal(new TunnelFrame(FrameType.UbusRes, f.StreamId, body).Encode()), WebSocketMessageType.Binary, true, ct);
                        }
                        else if (f.Type == FrameType.HttpReqMeta)
                        {
                            streams[f.StreamId] = (JsonSerializer.Deserialize<HttpRequestMeta>(f.Payload)!, new MemoryStream());
                        }
                        else if (f.Type == FrameType.HttpReqBody && streams.TryGetValue(f.StreamId, out var st))
                        {
                            st.Body.Write(f.Payload);
                        }
                        else if (f.Type == FrameType.HttpReqEnd && streams.TryRemove(f.StreamId, out var done))
                        {
                            var hReq = new HttpRequestMessage(new HttpMethod(done.Meta.Method), $"http://127.0.0.1:{luciPort}{done.Meta.Path}");
                            var hResp = await http.SendAsync(hReq, ct);
                            var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
                            foreach (var h in hResp.Headers) headers[h.Key] = h.Value.ToArray();
                            foreach (var h in hResp.Content.Headers) headers[h.Key] = h.Value.ToArray();
                            byte[] body = await hResp.Content.ReadAsByteArrayAsync(ct);

                            await ws.SendAsync(tc.Seal(new TunnelFrame(FrameType.HttpResMeta, f.StreamId,
                                JsonSerializer.SerializeToUtf8Bytes(new HttpResponseMeta { Status = (int)hResp.StatusCode, Headers = headers })).Encode()), WebSocketMessageType.Binary, true, ct);
                            await ws.SendAsync(tc.Seal(new TunnelFrame(FrameType.HttpResBody, f.StreamId, body).Encode()), WebSocketMessageType.Binary, true, ct);
                            await ws.SendAsync(tc.Seal(new TunnelFrame(FrameType.HttpResEnd, f.StreamId, []).Encode()), WebSocketMessageType.Binary, true, ct);
                        }
                    }
                }, ct);
            }
        }
    }

    private sealed class InProcessBlindRelay : IAsyncDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly ConcurrentBag<WebSocket> _nostrClients = [];
        private readonly ConcurrentDictionary<string, List<(string Role, WebSocket Ws)>> _rooms = new();
        private readonly CancellationTokenSource _cts = new();
        private Task? _loop;

        public int Port { get; private set; }
        public string WsBaseUrl => $"ws://127.0.0.1:{Port}";
        public ConcurrentBag<byte[]> ObservedTunnelFrames { get; } = [];

        public void Start()
        {
            using var probe = new TcpListener(IPAddress.Loopback, 0);
            probe.Start();
            Port = ((IPEndPoint)probe.LocalEndpoint).Port;
            probe.Stop();

            _listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
            _listener.Start();
            _loop = Task.Run(AcceptLoopAsync);
        }

        private async Task AcceptLoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try { ctx = await _listener.GetContextAsync(); }
                catch { break; }

                if (!ctx.Request.IsWebSocketRequest)
                {
                    ctx.Response.StatusCode = 400;
                    ctx.Response.Close();
                    continue;
                }

                var wsCtx = await ctx.AcceptWebSocketAsync(null);
                var ws = wsCtx.WebSocket;
                string path = ctx.Request.Url!.AbsolutePath;
                if (path.StartsWith("/tunnel/", StringComparison.Ordinal))
                {
                    string sid = path["/tunnel/".Length..];
                    string role = ctx.Request.QueryString["role"] ?? "client";
                    _ = Task.Run(() => HandleTunnelPeerAsync(sid, role, ws));
                }
                else
                {
                    _nostrClients.Add(ws);
                    _ = Task.Run(() => HandleNostrPeerAsync(ws));
                }
            }
        }

        private async Task HandleNostrPeerAsync(WebSocket ws)
        {
            byte[] buf = new byte[64 * 1024];
            try
            {
                while (!_cts.IsCancellationRequested && ws.State == WebSocketState.Open)
                {
                    var r = await ws.ReceiveAsync(buf, _cts.Token);
                    if (r.MessageType == WebSocketMessageType.Close) break;
                    string msg = Encoding.UTF8.GetString(buf, 0, r.Count);
                    using var doc = JsonDocument.Parse(msg);
                    string kind = doc.RootElement[0].GetString()!;
                    if (kind == "REQ")
                    {
                        string subId = doc.RootElement[1].GetString()!;
                        await ws.SendAsync(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new[] { "EOSE", subId })), WebSocketMessageType.Text, true, _cts.Token);
                    }
                    else if (kind == "EVENT")
                    {
                        var evt = doc.RootElement[1].Deserialize<NostrEvent>()!;
                        byte[] relayMsg = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new object[] { "EVENT", "sub", evt }, NostrEvent.CanonicalJsonOptions));
                        foreach (var peer in _nostrClients)
                        {
                            if (peer.State == WebSocketState.Open)
                            {
                                try { await peer.SendAsync(relayMsg, WebSocketMessageType.Text, true, _cts.Token); }
                                catch { /* Ignore closed peer */ }
                            }
                        }
                    }
                }
            }
            catch
            {
                // Peer disconnected
            }
        }

        private async Task HandleTunnelPeerAsync(string sid, string role, WebSocket ws)
        {
            var list = _rooms.GetOrAdd(sid, _ => []);
            lock (list) list.Add((role, ws));

            byte[] buf = new byte[64 * 1024];
            while (!_cts.IsCancellationRequested && ws.State == WebSocketState.Open)
            {
                var r = await ws.ReceiveAsync(buf, _cts.Token);
                if (r.MessageType == WebSocketMessageType.Close) break;
                byte[] copy = buf.AsSpan(0, r.Count).ToArray();
                ObservedTunnelFrames.Add(copy);
                List<(string Role, WebSocket Ws)> peers;
                lock (list) peers = list.ToList();
                foreach (var p in peers)
                {
                    if (p.Role != role && p.Ws.State == WebSocketState.Open)
                        await p.Ws.SendAsync(copy, r.MessageType, r.EndOfMessage, _cts.Token);
                }
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

    private sealed class InProcessMockLuciServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _cts = new();
        private Task? _loop;
        private int _staticHits;

        public int Port { get; private set; }
        public int StaticHits => Volatile.Read(ref _staticHits);

        public void Start()
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _loop = Task.Run(LoopAsync);
        }

        private async Task LoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await _listener.AcceptTcpClientAsync(_cts.Token); }
                catch { break; }
                _ = Task.Run(() => HandleAsync(client));
            }
        }

        private async Task HandleAsync(TcpClient client)
        {
            using (client)
            {
                await using var stream = client.GetStream();
                byte[] buf = new byte[8192];
                int n = await stream.ReadAsync(buf, _cts.Token);
                if (n <= 0) return;
                string firstLine = Encoding.UTF8.GetString(buf, 0, n).Split("\r\n")[0];
                string path = firstLine.Split(' ')[1];

                byte[] body;
                string contentType;
                string extra = "Set-Cookie: sysauth_http=testtoken; Path=/; HttpOnly; Secure\r\n";

                if (path.StartsWith("/luci-static/", StringComparison.Ordinal))
                {
                    Interlocked.Increment(ref _staticHits);
                    contentType = "application/javascript";
                    body = Encoding.UTF8.GetBytes("/* luci static js */");
                }
                else if (path.StartsWith("/ubus", StringComparison.Ordinal))
                {
                    contentType = "application/json";
                    body = Encoding.UTF8.GetBytes("""
                        [
                          {"jsonrpc":"2.0","id":1,"result":[0,{"hostname":"OpenWrt-Test-Router","model":"TestModel","kernel":"6.6","release":{"description":"24.10.0"}}]},
                          {"jsonrpc":"2.0","id":2,"result":[0,{"uptime":3600,"load":[6553,6553],"memory":{"total":268435456,"free":134217728}}]},
                          {"jsonrpc":"2.0","id":3,"result":[0,{"up":true,"ipv4-address":[{"address":"100.64.0.1"}]}]},
                          {"jsonrpc":"2.0","id":4,"result":[0,{"AA:BB:CC:DD:EE:FF":{}}]}
                        ]
                        """);
                }
                else
                {
                    contentType = "text/html; charset=utf-8";
                    body = Encoding.UTF8.GetBytes("<html><body><h1>OpenWrt LuCI E2EE Mock</h1></body></html>");
                }

                string head = $"HTTP/1.1 200 OK\r\nContent-Type: {contentType}\r\n{extra}Content-Length: {body.Length}\r\nConnection: close\r\n\r\n";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(head), _cts.Token);
                await stream.WriteAsync(body, _cts.Token);
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
}
