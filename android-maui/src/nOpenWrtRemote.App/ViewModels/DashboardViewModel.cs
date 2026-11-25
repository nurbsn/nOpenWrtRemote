using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using nOpenWrtRemote.App.Services;
using nOpenWrtRemote.Core.Network;

namespace nOpenWrtRemote.App.ViewModels;

public partial class DashboardViewModel : ObservableObject
{
    private readonly ConnectionManager _connectionManager;

    public DashboardViewModel(ConnectionManager connectionManager)
    {
        _connectionManager = connectionManager;
    }

    [ObservableProperty] private string _routerName = "OpenWrt";
    [ObservableProperty] private string _model = "-";
    [ObservableProperty] private string _release = "-";
    [ObservableProperty] private string _uptime = "-";
    [ObservableProperty] private string _load = "-";
    [ObservableProperty] private string _ramSummary = "-";
    [ObservableProperty] private double _ramProgress;
    [ObservableProperty] private string _wanStatus = "-";
    [ObservableProperty] private string _clientsCount = "-";
    [ObservableProperty] private string _latencyText = "-";
    [ObservableProperty] private string _statusBanner = "Tunel E2EE aktywny";
    [ObservableProperty] private bool _isBusy;

    [RelayCommand]
    public async Task LoadTelemetryAsync()
    {
        if (_connectionManager.ActiveSession is not { IsConnected: true } session)
        {
            StatusBanner = "Brak aktywnego tunelu.";
            return;
        }

        IsBusy = true;
        try
        {
            RouterName = _connectionManager.ActiveProfile?.Name ?? "OpenWrt";
            var snap = await UbusClient.FetchTelemetryAsync(session, _connectionManager.ActiveUbusSessionId);
            Model = snap.Model;
            Release = snap.OpenWrtRelease;
            Uptime = FormatUptime(snap.UptimeSeconds);
            Load = $"{snap.Load1Min:0.00} / {snap.Load5Min:0.00}";
            RamSummary = snap.TotalRamMb > 0
                ? $"{snap.TotalRamMb - snap.FreeRamMb} / {snap.TotalRamMb} MB ({snap.RamUsedPercent:0.#}%)"
                : "-";
            RamProgress = snap.RamUsedPercent / 100.0;
            WanStatus = snap.WanUp ? $"Połączono ({snap.WanIp})" : "Rozłączono";
            ClientsCount = snap.ConnectedDevicesCount.ToString();
            LatencyText = $"{snap.LatencyMs} ms";
            StatusBanner = $"E2EE AES-256-GCM • {snap.Hostname}";
        }
        catch (Exception ex)
        {
            StatusBanner = $"Błąd odczytu ubus: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task OpenFullLuciAsync()
    {
        await Shell.Current.GoToAsync("luci");
    }

    [RelayCommand]
    private async Task DisconnectAsync()
    {
        await _connectionManager.DisconnectAsync();
        await Shell.Current.GoToAsync("..");
    }

    private static string FormatUptime(long seconds)
    {
        var ts = TimeSpan.FromSeconds(seconds);
        return ts.Days > 0 ? $"{ts.Days}d {ts.Hours}h {ts.Minutes}m" : $"{ts.Hours}h {ts.Minutes}m";
    }
}
