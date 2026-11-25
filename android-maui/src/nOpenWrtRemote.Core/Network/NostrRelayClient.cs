using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using nOpenWrtRemote.Core.Protocol;

namespace nOpenWrtRemote.Core.Network;

public sealed class NostrRelayClient : IAsyncDisposable
{
    private readonly ClientWebSocket _ws = new();
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly Channel<NostrEvent> _events = Channel.CreateUnbounded<NostrEvent>();
    private readonly CancellationTokenSource _cts = new();
    private Task? _readLoop;

    public ChannelReader<NostrEvent> Events => _events.Reader;
    public bool IsConnected => _ws.State == WebSocketState.Open;

    public async Task ConnectAsync(string relayUrl, CancellationToken ct = default)
    {
        await _ws.ConnectAsync(new Uri(relayUrl), ct);
        _readLoop = Task.Run(() => ReadLoopAsync(_cts.Token));
    }

    public async Task SubscribeAsync(string subId, int[] kinds, string[] pTags, CancellationToken ct = default)
    {
        var filter = new Dictionary<string, object>
        {
            ["kinds"] = kinds,
            ["#p"] = pTags
        };
        string json = JsonSerializer.Serialize(new object[] { "REQ", subId, filter }, NostrEvent.CanonicalJsonOptions);
        await SendTextAsync(json, ct);
    }

    public async Task PublishEventAsync(NostrEvent evt, CancellationToken ct = default)
    {
        string json = JsonSerializer.Serialize(new object[] { "EVENT", evt }, NostrEvent.CanonicalJsonOptions);
        await SendTextAsync(json, ct);
    }

    public async Task CloseSubscriptionAsync(string subId, CancellationToken ct = default)
    {
        if (_ws.State != WebSocketState.Open) return;
        string json = JsonSerializer.Serialize(new object[] { "CLOSE", subId }, NostrEvent.CanonicalJsonOptions);
        await SendTextAsync(json, ct);
    }

    private async Task SendTextAsync(string text, CancellationToken ct)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        await _sendLock.WaitAsync(ct);
        try
        {
            await _ws.SendAsync(bytes, WebSocketMessageType.Text, true, ct);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        byte[] buffer = new byte[16 * 1024];
        using var ms = new MemoryStream();
        try
        {
            while (!ct.IsCancellationRequested && _ws.State == WebSocketState.Open)
            {
                ms.SetLength(0);
                WebSocketReceiveResult result;
                do
                {
                    result = await _ws.ReceiveAsync(buffer, ct);
                    if (result.MessageType == WebSocketMessageType.Close)
                        return;
                    ms.Write(buffer, 0, result.Count);
                } while (!result.EndOfMessage);

                if (result.MessageType != WebSocketMessageType.Text)
                    continue;

                string text = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
                if (text == "pong") continue;

                try
                {
                    using var doc = JsonDocument.Parse(text);
                    if (doc.RootElement.ValueKind != JsonValueKind.Array || doc.RootElement.GetArrayLength() < 3)
                        continue;

                    if (doc.RootElement[0].GetString() == "EVENT")
                    {
                        var evt = doc.RootElement[2].Deserialize<NostrEvent>();
                        if (evt is not null && evt.Verify())
                            await _events.Writer.WriteAsync(evt, ct);
                    }
                }
                catch
                {
                    // Ignore malformed relay frames
                }
            }
        }
        catch
        {
            // Socket closed or cancelled
        }
        finally
        {
            _events.Writer.TryComplete();
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_ws.State == WebSocketState.Open)
        {
            try
            {
                await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", CancellationToken.None);
            }
            catch
            {
                // Ignore close errors
            }
        }
        if (_readLoop is not null)
        {
            try { await _readLoop; } catch { }
        }
        _ws.Dispose();
        _sendLock.Dispose();
        _cts.Dispose();
    }
}
