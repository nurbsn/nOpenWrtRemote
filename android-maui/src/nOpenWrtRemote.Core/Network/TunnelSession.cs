using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using nOpenWrtRemote.Core.Crypto;
using nOpenWrtRemote.Core.Models;
using nOpenWrtRemote.Core.Protocol;

namespace nOpenWrtRemote.Core.Network;

public sealed class TunnelSession : ITunnelHttpTransport, IAsyncDisposable
{
    private readonly ClientWebSocket _tunnelWs;
    private readonly TunnelCrypto _crypto;
    private readonly SemaphoreSlim _txLock = new(1, 1);
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<uint, PendingHttpStream> _httpStreams = new();
    private readonly ConcurrentDictionary<uint, TaskCompletionSource<byte[]>> _ubusStreams = new();
    private readonly Task _rxLoop;
    private readonly Task _pingLoop;
    private uint _nextStreamId;
    private int _latencyMs;

    private sealed class PendingHttpStream
    {
        public HttpResponseMeta? Meta;
        public readonly MemoryStream Body = new();
        public readonly TaskCompletionSource<HttpProxyResponse> Tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private TunnelSession(ClientWebSocket tunnelWs, TunnelCrypto crypto, string sessionId)
    {
        _tunnelWs = tunnelWs;
        _crypto = crypto;
        SessionId = sessionId;
        _rxLoop = Task.Run(() => ReceiveLoopAsync(_cts.Token));
        _pingLoop = Task.Run(() => PingLoopAsync(_cts.Token));
    }

    public string SessionId { get; }
    public int LatencyMs => Volatile.Read(ref _latencyMs);
    public bool IsConnected => _tunnelWs.State == WebSocketState.Open;

    public static async Task<RouterProfile> PairAsync(
        byte[] clientPrivKey32,
        PairingUri pairing,
        string deviceName,
        CancellationToken ct = default)
    {
        byte[] clientPub32 = NostrCrypto.GetXOnlyPubKey(clientPrivKey32);
        string clientPubHex = Convert.ToHexStringLower(clientPub32);
        byte[] convKey = Nip44.GetConversationKey(clientPrivKey32, pairing.RouterPubKey32);

        await using var relay = new NostrRelayClient();
        await relay.ConnectAsync(pairing.RelayUrl, ct);

        string subId = "pair-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(6));
        await relay.SubscribeAsync(subId, [NortConstants.KindResponse], [clientPubHex], ct);

        string reqId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        var req = new PairRequestMessage
        {
            ReqId = reqId,
            Ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Secret = pairing.Secret,
            DeviceName = string.IsNullOrWhiteSpace(deviceName) ? "Android" : deviceName
        };

        string encrypted = Nip44.Encrypt(JsonSerializer.Serialize(req), convKey);
        var evt = NostrEvent.CreateSigned(
            clientPrivKey32,
            NortConstants.KindRequest,
            [["p", pairing.RouterPubHex]],
            encrypted);

        await relay.PublishEventAsync(evt, ct);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(20));

        await foreach (var incoming in relay.Events.ReadAllAsync(timeoutCts.Token))
        {
            if (incoming.Kind != NortConstants.KindResponse ||
                !string.Equals(incoming.PubKey, pairing.RouterPubHex, StringComparison.OrdinalIgnoreCase))
                continue;

            string decrypted;
            try
            {
                decrypted = Nip44.Decrypt(incoming.Content, convKey);
            }
            catch
            {
                continue;
            }

            var ack = JsonSerializer.Deserialize<PairAckMessage>(decrypted);
            if (ack is null || ack.Type != "pair_ack" || ack.ReqId != reqId)
                continue;

            if (!ack.Ok)
                throw new InvalidOperationException($"Parowanie odrzucone przez router: {ack.Error ?? "unknown error"}");

            return new RouterProfile
            {
                Name = string.IsNullOrWhiteSpace(ack.RouterName) ? pairing.RouterName : ack.RouterName!,
                RouterNpub = pairing.RouterNpub,
                RouterPubHex = pairing.RouterPubHex,
                Relays = [pairing.RelayUrl],
                LanIp = pairing.LanIp,
                PairedAt = DateTimeOffset.UtcNow
            };
        }

        throw new TimeoutException("Router nie odpowiedział na żądanie parowania w wyznaczonym czasie.");
    }

    public static async Task<TunnelSession> ConnectAsync(
        byte[] clientPrivKey32,
        RouterProfile profile,
        CancellationToken ct = default)
    {
        string relayUrl = profile.Relays.FirstOrDefault() ?? NortConstants.DefaultRelay;
        byte[] clientPub32 = NostrCrypto.GetXOnlyPubKey(clientPrivKey32);
        string clientPubHex = Convert.ToHexStringLower(clientPub32);
        byte[] routerPub32 = Convert.FromHexString(profile.RouterPubHex);
        byte[] convKey = Nip44.GetConversationKey(clientPrivKey32, routerPub32);

        string sessionId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        string clientToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        string routerToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        string peerHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(routerToken)));

        var (cEphPriv, cEphPub) = NostrCrypto.GenerateKeyPair();

        var baseRelayUri = new Uri(relayUrl);
        string tunnelBaseUrl = $"{baseRelayUri.Scheme}://{baseRelayUri.Authority}/tunnel/{sessionId}";
        string clientWsUrl = $"{tunnelBaseUrl}?role=client&token={clientToken}&peer_hash={peerHash}";

        var tunnelWs = new ClientWebSocket();
        await tunnelWs.ConnectAsync(new Uri(clientWsUrl), ct);

        try
        {
            await using var nostr = new NostrRelayClient();
            await nostr.ConnectAsync(relayUrl, ct);

            string subId = "tun-" + sessionId[..10];
            await nostr.SubscribeAsync(subId, [NortConstants.KindResponse], [clientPubHex], ct);

            string reqId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
            var openMsg = new TunnelOpenMessage
            {
                ReqId = reqId,
                Ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                SessionId = sessionId,
                RelayTunnelUrl = tunnelBaseUrl,
                RouterToken = routerToken,
                ClientEphPub = Convert.ToHexStringLower(cEphPub)
            };

            string encrypted = Nip44.Encrypt(JsonSerializer.Serialize(openMsg), convKey);
            var evt = NostrEvent.CreateSigned(
                clientPrivKey32,
                NortConstants.KindRequest,
                [["p", profile.RouterPubHex]],
                encrypted);

            await nostr.PublishEventAsync(evt, ct);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(20));

            await foreach (var incoming in nostr.Events.ReadAllAsync(timeoutCts.Token))
            {
                if (incoming.Kind != NortConstants.KindResponse ||
                    !string.Equals(incoming.PubKey, profile.RouterPubHex, StringComparison.OrdinalIgnoreCase))
                    continue;

                string decrypted;
                try
                {
                    decrypted = Nip44.Decrypt(incoming.Content, convKey);
                }
                catch
                {
                    continue;
                }

                var ack = JsonSerializer.Deserialize<TunnelAckMessage>(decrypted);
                if (ack is null || ack.Type != "tunnel_ack" || ack.ReqId != reqId)
                    continue;

                if (!ack.Ok || string.IsNullOrWhiteSpace(ack.RouterEphPub))
                    throw new InvalidOperationException($"Router odrzucił otwarcie tunelu: {ack.Error ?? "unknown"}");

                byte[] routerEphPub = Convert.FromHexString(ack.RouterEphPub);
                var crypto = new TunnelCrypto(
                    isRouter: false,
                    localEphPriv32: cEphPriv,
                    remoteEphXOnlyPub32: routerEphPub,
                    clientIdentityPub32: clientPub32,
                    routerIdentityPub32: routerPub32,
                    sessionId: sessionId,
                    clientEphPub32: cEphPub,
                    routerEphPub32: routerEphPub);

                return new TunnelSession(tunnelWs, crypto, sessionId);
            }

            throw new TimeoutException("Przekroczono czas oczekiwania na odpowiedź tunnel_ack z routera.");
        }
        catch
        {
            tunnelWs.Dispose();
            throw;
        }
    }

    public async Task<HttpProxyResponse> SendHttpAsync(HttpProxyRequest request, CancellationToken ct = default)
    {
        uint streamId = Interlocked.Increment(ref _nextStreamId);
        var pending = new PendingHttpStream();
        _httpStreams[streamId] = pending;

        try
        {
            var meta = new HttpRequestMeta
            {
                Method = request.Method,
                Path = request.Path,
                Headers = request.Headers
            };
            byte[] metaBytes = JsonSerializer.SerializeToUtf8Bytes(meta);
            await SendFrameAsync(new TunnelFrame(FrameType.HttpReqMeta, streamId, metaBytes), ct);

            const int chunkSize = 32 * 1024;
            int offset = 0;
            while (offset < request.Body.Length)
            {
                int count = Math.Min(chunkSize, request.Body.Length - offset);
                byte[] chunk = request.Body.AsSpan(offset, count).ToArray();
                await SendFrameAsync(new TunnelFrame(FrameType.HttpReqBody, streamId, chunk), ct);
                offset += count;
            }

            await SendFrameAsync(new TunnelFrame(FrameType.HttpReqEnd, streamId, []), ct);

            using var reg = ct.Register(() => pending.Tcs.TrySetCanceled(ct));
            return await pending.Tcs.Task;
        }
        catch
        {
            _httpStreams.TryRemove(streamId, out _);
            throw;
        }
    }

    public async Task<byte[]> SendUbusRawAsync(byte[] jsonRpcBody, CancellationToken ct = default)
    {
        uint streamId = Interlocked.Increment(ref _nextStreamId);
        var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        _ubusStreams[streamId] = tcs;

        try
        {
            await SendFrameAsync(new TunnelFrame(FrameType.UbusReq, streamId, jsonRpcBody), ct);
            using var reg = ct.Register(() => tcs.TrySetCanceled(ct));
            return await tcs.Task;
        }
        catch
        {
            _ubusStreams.TryRemove(streamId, out _);
            throw;
        }
    }

    private async Task SendFrameAsync(TunnelFrame frame, CancellationToken ct)
    {
        byte[] envelope = _crypto.Seal(frame.Encode());
        await _txLock.WaitAsync(ct);
        try
        {
            await _tunnelWs.SendAsync(envelope, WebSocketMessageType.Binary, true, ct);
        }
        finally
        {
            _txLock.Release();
        }
    }

    private async Task PingLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested && _tunnelWs.State == WebSocketState.Open)
            {
                byte[] payload = new byte[8];
                BinaryPrimitives.WriteInt64BigEndian(payload, Environment.TickCount64);
                await SendFrameAsync(new TunnelFrame(FrameType.Ping, 0, payload), ct);
                await Task.Delay(TimeSpan.FromSeconds(20), ct);
            }
        }
        catch
        {
            // Session ended
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        byte[] buf = new byte[64 * 1024];
        using var ms = new MemoryStream();
        try
        {
            while (!ct.IsCancellationRequested && _tunnelWs.State == WebSocketState.Open)
            {
                ms.SetLength(0);
                WebSocketReceiveResult res;
                do
                {
                    res = await _tunnelWs.ReceiveAsync(buf, ct);
                    if (res.MessageType == WebSocketMessageType.Close)
                        return;
                    ms.Write(buf, 0, res.Count);
                } while (!res.EndOfMessage);

                if (res.MessageType != WebSocketMessageType.Binary)
                    continue;

                byte[] plain = _crypto.Open(ms.GetBuffer().AsSpan(0, (int)ms.Length));
                var frame = TunnelFrame.Decode(plain);

                switch (frame.Type)
                {
                    case FrameType.Pong when frame.Payload.Length == 8:
                        long sentTick = BinaryPrimitives.ReadInt64BigEndian(frame.Payload);
                        Volatile.Write(ref _latencyMs, (int)Math.Max(0, Environment.TickCount64 - sentTick));
                        break;

                    case FrameType.UbusRes:
                        if (_ubusStreams.TryRemove(frame.StreamId, out var ubusTcs))
                            ubusTcs.TrySetResult(frame.Payload);
                        break;

                    case FrameType.HttpResMeta:
                        if (_httpStreams.TryGetValue(frame.StreamId, out var stMeta))
                            stMeta.Meta = JsonSerializer.Deserialize<HttpResponseMeta>(frame.Payload);
                        break;

                    case FrameType.HttpResBody:
                        if (_httpStreams.TryGetValue(frame.StreamId, out var stBody))
                            stBody.Body.Write(frame.Payload);
                        break;

                    case FrameType.HttpResEnd:
                        if (_httpStreams.TryRemove(frame.StreamId, out var stEnd))
                        {
                            var meta = stEnd.Meta ?? new HttpResponseMeta();
                            stEnd.Tcs.TrySetResult(new HttpProxyResponse(meta.Status, meta.Headers, stEnd.Body.ToArray()));
                        }
                        break;

                    case FrameType.HttpRst:
                        string err = Encoding.UTF8.GetString(frame.Payload);
                        if (_httpStreams.TryRemove(frame.StreamId, out var stRst))
                            stRst.Tcs.TrySetException(new IOException($"Tunnel stream reset: {err}"));
                        if (_ubusStreams.TryRemove(frame.StreamId, out var uRst))
                            uRst.TrySetException(new IOException($"Tunnel ubus reset: {err}"));
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            FailPending(ex);
        }
        finally
        {
            FailPending(new IOException("Tunnel closed."));
        }
    }

    private void FailPending(Exception ex)
    {
        foreach (var kv in _httpStreams)
        {
            if (_httpStreams.TryRemove(kv.Key, out var st))
                st.Tcs.TrySetException(ex);
        }
        foreach (var kv in _ubusStreams)
        {
            if (_ubusStreams.TryRemove(kv.Key, out var tcs))
                tcs.TrySetException(ex);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_tunnelWs.State == WebSocketState.Open)
        {
            try { await _tunnelWs.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", CancellationToken.None); } catch { }
        }
        try { await _rxLoop; } catch { }
        try { await _pingLoop; } catch { }
        _tunnelWs.Dispose();
        _crypto.Dispose();
        _txLock.Dispose();
        _cts.Dispose();
    }
}
