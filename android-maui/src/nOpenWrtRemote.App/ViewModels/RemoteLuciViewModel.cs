using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using nOpenWrtRemote.App.Services;

namespace nOpenWrtRemote.App.ViewModels;

public partial class RemoteLuciViewModel : ObservableObject
{
    private readonly ConnectionManager _connectionManager;

    public RemoteLuciViewModel(ConnectionManager connectionManager)
    {
        _connectionManager = connectionManager;
    }

    [ObservableProperty] private string _entryUrl = "about:blank";
    [ObservableProperty] private string _allowedBaseUrl = "http://127.0.0.1";
    [ObservableProperty] private string _tunnelBadge = "E2EE Aktywne";
    [ObservableProperty] private string _cacheStats = "Cache: 0";

    public void RefreshState()
    {
        var proxy = _connectionManager.ActiveProxy;
        var session = _connectionManager.ActiveSession;
        if (proxy is not null && session is { IsConnected: true })
        {
            AllowedBaseUrl = proxy.BaseUrl;
            EntryUrl = proxy.EntryUrl;
            TunnelBadge = $"E2EE • {session.LatencyMs} ms";
            CacheStats = $"Cache: {proxy.CacheHits} hit";
        }
    }

    [RelayCommand]
    private async Task BackToDashboardAsync()
    {
        await Shell.Current.GoToAsync("..");
    }
}
