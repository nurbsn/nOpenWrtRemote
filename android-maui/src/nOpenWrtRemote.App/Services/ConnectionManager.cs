using nOpenWrtRemote.Core.Models;
using nOpenWrtRemote.Core.Network;

namespace nOpenWrtRemote.App.Services;

public sealed class ConnectionManager : IAsyncDisposable
{
    private readonly IdentityService _identityService;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public ConnectionManager(IdentityService identityService)
    {
        _identityService = identityService;
    }

    public RouterProfile? ActiveProfile { get; private set; }
    public TunnelSession? ActiveSession { get; private set; }
    public LocalLuciProxyServer? ActiveProxy { get; private set; }
    public string? ActiveUbusSessionId { get; set; }

    public async Task ConnectRouterAsync(RouterProfile profile, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            if (ActiveSession is not null &&
                ActiveSession.IsConnected &&
                ActiveProfile?.RouterPubHex == profile.RouterPubHex)
            {
                return;
            }

            await DisconnectInternalAsync();

            byte[] privKey = await _identityService.GetOrCreatePrivateKeyAsync();
            var session = await TunnelSession.ConnectAsync(privKey, profile, ct);
            var proxy = new LocalLuciProxyServer(session);
            proxy.Start();

            ActiveProfile = profile;
            ActiveSession = session;
            ActiveProxy = proxy;
            ActiveUbusSessionId = null;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task DisconnectAsync()
    {
        await _lock.WaitAsync();
        try
        {
            await DisconnectInternalAsync();
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task DisconnectInternalAsync()
    {
        ActiveUbusSessionId = null;
        ActiveProfile = null;
        if (ActiveProxy is not null)
        {
            await ActiveProxy.DisposeAsync();
            ActiveProxy = null;
        }
        if (ActiveSession is not null)
        {
            await ActiveSession.DisposeAsync();
            ActiveSession = null;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await DisconnectInternalAsync();
        _lock.Dispose();
    }
}
