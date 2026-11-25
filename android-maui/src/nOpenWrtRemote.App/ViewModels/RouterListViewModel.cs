using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using nOpenWrtRemote.App.Services;
using nOpenWrtRemote.Core.Models;

namespace nOpenWrtRemote.App.ViewModels;

public partial class RouterListViewModel : ObservableObject
{
    private readonly RouterStoreService _store;
    private readonly ConnectionManager _connectionManager;
    private readonly BiometricAuthService _biometric;
    private bool _unlocked;

    public RouterListViewModel(
        RouterStoreService store,
        ConnectionManager connectionManager,
        BiometricAuthService biometric)
    {
        _store = store;
        _connectionManager = connectionManager;
        _biometric = biometric;
    }

    public ObservableCollection<RouterProfile> Routers { get; } = [];

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string _statusMessage = string.Empty;

    [ObservableProperty]
    private bool _hasRouters;

    public async Task InitializeAsync()
    {
        if (_store.BiometricEnabled && !_unlocked)
        {
            bool ok = await _biometric.AuthenticateAsync(
                "Odblokuj nOpenWrtRemote",
                "Potwierdź tożsamość, aby uzyskać dostęp do kluczy Nostr");
            if (!ok)
            {
                StatusMessage = "Wymagana autoryzacja biometryczna.";
                return;
            }
            _unlocked = true;
        }

        await RefreshAsync();

        string? pendingUri = DeepLinkInbox.ConsumePendingPairUri();
        if (!string.IsNullOrWhiteSpace(pendingUri))
        {
            await Shell.Current.GoToAsync($"pair?uri={Uri.EscapeDataString(pendingUri)}");
        }
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        var items = await _store.LoadRoutersAsync();
        Routers.Clear();
        foreach (var item in items)
            Routers.Add(item);
        HasRouters = Routers.Count > 0;
    }

    [RelayCommand]
    private async Task GoToPairAsync()
    {
        await Shell.Current.GoToAsync("pair");
    }

    [RelayCommand]
    private async Task GoToSettingsAsync()
    {
        await Shell.Current.GoToAsync("settings");
    }

    [RelayCommand]
    private async Task ConnectAsync(RouterProfile profile)
    {
        if (IsBusy) return;
        IsBusy = true;
        StatusMessage = $"Zestawianie tunelu E2EE z {profile.Name}...";
        try
        {
            await _connectionManager.ConnectRouterAsync(profile);
            profile.LastConnectedAt = DateTimeOffset.UtcNow;
            await _store.UpsertRouterAsync(profile);
            StatusMessage = string.Empty;
            await Shell.Current.GoToAsync("dashboard");
        }
        catch (Exception ex)
        {
            StatusMessage = $"Błąd połączenia: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task RemoveAsync(RouterProfile profile)
    {
        await _store.RemoveRouterAsync(profile.Id);
        await RefreshAsync();
    }
}
