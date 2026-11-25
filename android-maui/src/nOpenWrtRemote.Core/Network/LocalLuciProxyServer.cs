using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using nOpenWrtRemote.Core.Protocol;

namespace nOpenWrtRemote.Core.Network;

/// <summary>
/// Loopback-only HTTP/1.1 proxy server (127.0.0.1) bridging Android WebView to the E2EE NORT-1 tunnel.
/// Enforces single-session HttpOnly cookie authentication and caches /luci-static/* assets locally.
/// </summary>
public sealed class LocalLuciProxyServer : IAsyncDisposable
{
    public const string SessionCookieName = "__nort_local_session";

    private sealed record CachedAsset(int StatusCode, Dictionary<string, string[]> Headers, byte[] Body);

    private readonly ITunnelHttpTransport _transport;
    private readonly TcpListener _listener;
    private readonly string _authToken;
    private readonly string _sessionCookieValue;
    private readonly ConcurrentDictionary<string, CachedAsset> _staticCache = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _cts = new();
    private Task? _acceptLoop;
    private long _cacheHits;
    private long _cacheMisses;

    public LocalLuciProxyServer(ITunnelHttpTransport transport)
    {
        _transport = transport;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _authToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        _sessionCookieValue = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
    }

    public int Port { get; private set; }
    public long CacheHits => Interlocked.Read(ref _cacheHits);
    public long CacheMisses => Interlocked.Read(ref _cacheMisses);

    public string EntryUrl => $"http://127.0.0.1:{Port}/__nort_auth?token={_authToken}";
    public string BaseUrl => $"http://127.0.0.1:{Port}";

    public void Start()
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
    }

    public void ClearCache() => _staticCache.Clear();

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client = await _listener.AcceptTcpClientAsync(ct);
                _ = Task.Run(() => HandleClientAsync(client, ct), ct);
            }
        }
        catch
        {
            // Listener stopped
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            try
            {
                await using var stream = client.GetStream();
                var req = await ReadHttpRequestAsync(stream, ct);
                if (req is null) return;

                if (req.Path.StartsWith("/__nort_auth", StringComparison.Ordinal))
                {
                    await HandleAuthHandshakeAsync(stream, req.Path, ct);
                    return;
                }

                if (!HasValidLocalSessionCookie(req.Headers))
                {
                    await WriteHttpResponseAsync(
                        stream,
                        403,
                        new Dictionary<string, string[]> { ["Content-Type"] = ["text/plain; charset=utf-8"] },
                        Encoding.UTF8.GetBytes("403 Forbidden: missing or invalid local proxy session"),
                        ct);
                    return;
                }

                var sanitizedHeaders = SanitizeOutgoingHeaders(req.Headers);

                HttpProxyResponse? proxyResp = null;
                bool isStaticGet = string.Equals(req.Method, "GET", StringComparison.OrdinalIgnoreCase) &&
                                   req.Path.StartsWith("/luci-static/", StringComparison.Ordinal);

                if (isStaticGet && _staticCache.TryGetValue(req.Path, out var cached))
                {
                    Interlocked.Increment(ref _cacheHits);
                    proxyResp = new HttpProxyResponse(cached.StatusCode, CloneHeaders(cached.Headers), cached.Body);
                }
                else
                {
                    if (isStaticGet) Interlocked.Increment(ref _cacheMisses);

                    proxyResp = await _transport.SendHttpAsync(
                        new HttpProxyRequest(req.Method, req.Path, sanitizedHeaders, req.Body),
                        ct);

                    if (isStaticGet && proxyResp.StatusCode == 200 && proxyResp.Body.Length <= 2 * 1024 * 1024)
                    {
                        _staticCache[req.Path] = new CachedAsset(proxyResp.StatusCode, CloneHeaders(proxyResp.Headers), proxyResp.Body);
                    }
                }

                var outHeaders = RewriteIncomingHeaders(proxyResp.Headers);
                await WriteHttpResponseAsync(stream, proxyResp.StatusCode, outHeaders, proxyResp.Body, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                try
                {
                    await using var stream = client.GetStream();
                    await WriteHttpResponseAsync(
                        stream,
                        502,
                        new Dictionary<string, string[]> { ["Content-Type"] = ["text/plain; charset=utf-8"] },
                        Encoding.UTF8.GetBytes($"502 Bad Gateway (E2EE Tunnel): {ex.Message}"),
                        CancellationToken.None);
                }
                catch
                {
                    // Client disconnected
                }
            }
        }
    }

    private async Task HandleAuthHandshakeAsync(NetworkStream stream, string path, CancellationToken ct)
    {
        int qIdx = path.IndexOf('?');
        string? token = null;
        if (qIdx >= 0)
        {
            foreach (string part in path[(qIdx + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = part.IndexOf('=');
                if (eq > 0 && part[..eq] == "token")
                    token = Uri.UnescapeDataString(part[(eq + 1)..]);
            }
        }

        if (token is null || !CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(token),
                Encoding.UTF8.GetBytes(_authToken)))
        {
            await WriteHttpResponseAsync(
                stream,
                403,
                new Dictionary<string, string[]> { ["Content-Type"] = ["text/plain; charset=utf-8"] },
                Encoding.UTF8.GetBytes("403 Forbidden: invalid auth token"),
                ct);
            return;
        }

        var headers = new Dictionary<string, string[]>
        {
            ["Set-Cookie"] = [$"{SessionCookieName}={_sessionCookieValue}; Path=/; HttpOnly; SameSite=Strict"],
            ["Location"] = ["/cgi-bin/luci"],
            ["Cache-Control"] = ["no-store"]
        };
        await WriteHttpResponseAsync(stream, 302, headers, [], ct);
    }

    private bool HasValidLocalSessionCookie(Dictionary<string, string[]> headers)
    {
        if (!TryGetHeader(headers, "Cookie", out string[]? cookieValues))
            return false;

        foreach (string rawHeader in cookieValues)
        {
            foreach (string pair in rawHeader.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = pair.IndexOf('=');
                if (eq <= 0) continue;
                string name = pair[..eq].Trim();
                string value = pair[(eq + 1)..].Trim();
                if (name == SessionCookieName &&
                    CryptographicOperations.FixedTimeEquals(
                        Encoding.UTF8.GetBytes(value),
                        Encoding.UTF8.GetBytes(_sessionCookieValue)))
                {
                    return true;
                }
            }
        }
        return false;
    }

    private static Dictionary<string, string[]> SanitizeOutgoingHeaders(Dictionary<string, string[]> headers)
    {
        var result = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, vals) in headers)
        {
            if (key.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("Connection", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
                continue;

            if (key.Equals("Cookie", StringComparison.OrdinalIgnoreCase))
            {
                var kept = new List<string>();
                foreach (string raw in vals)
                {
                    var filteredPairs = raw.Split(';', StringSplitOptions.RemoveEmptyEntries)
                        .Select(p => p.Trim())
                        .Where(p => !p.StartsWith(SessionCookieName + "=", StringComparison.Ordinal))
                        .ToArray();
                    if (filteredPairs.Length > 0)
                        kept.Add(string.Join("; ", filteredPairs));
                }
                if (kept.Count > 0)
                    result["Cookie"] = kept.ToArray();
                continue;
            }

            result[key] = vals;
        }
        return result;
    }

    private Dictionary<string, string[]> RewriteIncomingHeaders(Dictionary<string, string[]> headers)
    {
        var result = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, vals) in headers)
        {
            if (key.Equals("Strict-Transport-Security", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("Connection", StringComparison.OrdinalIgnoreCase))
                continue;

            if (key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
            {
                // Strip ; Secure ONLY on local 127.0.0.1 loopback hop so WebView submits LuCI's sysauth cookie.
                result[key] = vals.Select(StripSecureAttribute).ToArray();
                continue;
            }

            if (key.Equals("Location", StringComparison.OrdinalIgnoreCase))
            {
                result[key] = vals.Select(loc =>
                {
                    if (Uri.TryCreate(loc, UriKind.Absolute, out var u))
                        return $"http://127.0.0.1:{Port}{u.PathAndQuery}";
                    return loc;
                }).ToArray();
                continue;
            }

            result[key] = vals;
        }
        return result;
    }

    private static string StripSecureAttribute(string cookieHeader)
    {
        var parts = cookieHeader.Split(';')
            .Select(p => p.Trim())
            .Where(p => !p.Equals("Secure", StringComparison.OrdinalIgnoreCase) &&
                        !p.StartsWith("Domain=", StringComparison.OrdinalIgnoreCase));
        return string.Join("; ", parts);
    }

    private static Dictionary<string, string[]> CloneHeaders(Dictionary<string, string[]> src)
    {
        var copy = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in src)
            copy[k] = v.ToArray();
        return copy;
    }

    private static bool TryGetHeader(Dictionary<string, string[]> headers, string name, out string[] values)
    {
        foreach (var (k, v) in headers)
        {
            if (k.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                values = v;
                return true;
            }
        }
        values = [];
        return false;
    }

    private sealed record ParsedHttpRequest(string Method, string Path, Dictionary<string, string[]> Headers, byte[] Body);

    private static async Task<ParsedHttpRequest?> ReadHttpRequestAsync(NetworkStream stream, CancellationToken ct)
    {
        var headerBuf = new MemoryStream();
        byte[] one = new byte[1];
        int match = 0;
        while (headerBuf.Length < 64 * 1024)
        {
            int n = await stream.ReadAsync(one, ct);
            if (n == 0) return null;
            byte b = one[0];
            headerBuf.WriteByte(b);
            match = (match, b) switch
            {
                (0, (byte)'\r') => 1,
                (1, (byte)'\n') => 2,
                (2, (byte)'\r') => 3,
                (3, (byte)'\n') => 4,
                (_, (byte)'\r') => 1,
                _ => 0
            };
            if (match == 4) break;
        }

        string headerText = Encoding.ASCII.GetString(headerBuf.GetBuffer(), 0, (int)headerBuf.Length);
        string[] lines = headerText.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 0) return null;

        string[] reqLine = lines[0].Split(' ', 3);
        if (reqLine.Length < 2) return null;
        string method = reqLine[0].ToUpperInvariant();
        string rawTarget = reqLine[1];
        if (Uri.TryCreate(rawTarget, UriKind.Absolute, out var abs))
            rawTarget = abs.PathAndQuery;
        if (!rawTarget.StartsWith('/')) rawTarget = "/" + rawTarget;

        var headers = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        for (int i = 1; i < lines.Length; i++)
        {
            int colon = lines[i].IndexOf(':');
            if (colon <= 0) continue;
            string name = lines[i][..colon].Trim();
            string val = lines[i][(colon + 1)..].Trim();
            if (!headers.TryGetValue(name, out var list))
            {
                list = [];
                headers[name] = list;
            }
            list.Add(val);
        }

        byte[] body = [];
        if (headers.TryGetValue("Transfer-Encoding", out var te) &&
            te.Any(v => v.Contains("chunked", StringComparison.OrdinalIgnoreCase)))
        {
            body = await ReadChunkedBodyAsync(stream, ct);
        }
        else if (headers.TryGetValue("Content-Length", out var cl) &&
                 int.TryParse(cl[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out int contentLength) &&
                 contentLength > 0)
        {
            body = new byte[contentLength];
            await stream.ReadExactlyAsync(body, ct);
        }

        var headerDict = headers.ToDictionary(kv => kv.Key, kv => kv.Value.ToArray(), StringComparer.OrdinalIgnoreCase);
        return new ParsedHttpRequest(method, rawTarget, headerDict, body);
    }

    private static async Task<byte[]> ReadChunkedBodyAsync(NetworkStream stream, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        while (true)
        {
            string sizeLine = await ReadLineAsync(stream, ct);
            int semi = sizeLine.IndexOf(';');
            if (semi >= 0) sizeLine = sizeLine[..semi];
            int chunkLen = int.Parse(sizeLine.Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            if (chunkLen == 0)
            {
                // consume trailing CRLF
                await ReadLineAsync(stream, ct);
                break;
            }
            byte[] chunk = new byte[chunkLen];
            await stream.ReadExactlyAsync(chunk, ct);
            ms.Write(chunk);
            await ReadLineAsync(stream, ct);
        }
        return ms.ToArray();
    }

    private static async Task<string> ReadLineAsync(NetworkStream stream, CancellationToken ct)
    {
        var buf = new MemoryStream();
        byte[] one = new byte[1];
        while (true)
        {
            int n = await stream.ReadAsync(one, ct);
            if (n == 0) break;
            if (one[0] == (byte)'\n') break;
            if (one[0] != (byte)'\r') buf.WriteByte(one[0]);
        }
        return Encoding.ASCII.GetString(buf.GetBuffer(), 0, (int)buf.Length);
    }

    private static async Task WriteHttpResponseAsync(
        NetworkStream stream,
        int statusCode,
        Dictionary<string, string[]> headers,
        byte[] body,
        CancellationToken ct)
    {
        string reason = statusCode switch
        {
            200 => "OK",
            302 => "Found",
            304 => "Not Modified",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            502 => "Bad Gateway",
            _ => "OK"
        };

        var sb = new StringBuilder();
        sb.Append($"HTTP/1.1 {statusCode} {reason}\r\n");
        foreach (var (k, vals) in headers)
        {
            foreach (string v in vals)
                sb.Append($"{k}: {v}\r\n");
        }
        sb.Append($"Content-Length: {body.Length}\r\n");
        sb.Append("Connection: close\r\n\r\n");

        byte[] headerBytes = Encoding.ASCII.GetBytes(sb.ToString());
        await stream.WriteAsync(headerBytes, ct);
        if (body.Length > 0)
            await stream.WriteAsync(body, ct);
        await stream.FlushAsync(ct);
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _listener.Stop();
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop; } catch { }
        }
        _cts.Dispose();
    }
}
