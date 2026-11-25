using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using nOpenWrtRemote.App.Services;

namespace nOpenWrtRemote.App.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly IdentityService _identity;
    private readonly RouterStoreService _store;
    private readonly ConnectionManager _connectionManager;

    public SettingsViewModel(
        IdentityService identity,
        RouterStoreService store,
        ConnectionManager connectionManager)
    {
        _identity = identity;
        _store = store;
        _connectionManager = connectionManager;
    }

    [ObservableProperty] private string _deviceNpub = "Ładowanie...";
    [ObservableProperty] private string _defaultRelay = "wss://relay.gfmm.eu";
    [ObservableProperty] private bool _biometricEnabled;
    [ObservableProperty] private string _infoMessage = string.Empty;

    public async Task LoadAsync()
    {
        DeviceNpub = await _identity.GetNpubAsync();
        DefaultRelay = _store.DefaultRelay;
        BiometricEnabled = _store.BiometricEnabled;
    }

    partial void OnBiometricEnabledChanged(bool value)
    {
        _store.BiometricEnabled = value;
    }

    [RelayCommand]
    private async Task SaveRelayAsync()
    {
        _store.DefaultRelay = DefaultRelay;
        InfoMessage = "Zapisano domyślny relay Nostr.";
        await Task.CompletedTask;
    }

    [RelayCommand]
    private async Task CopyNpubAsync()
    {
        await Clipboard.Default.SetTextAsync(DeviceNpub);
        InfoMessage = "Skopiowano npub urządzenia do schowka.";
    }

    [RelayCommand]
    private void ClearLuciCache()
    {
        _connectionManager.ActiveProxy?.ClearCache();
        InfoMessage = "Wyczyszczono pamięć podręczną /luci-static/*.";
    }

    [RelayCommand]
    private async Task OpenPrivacyPolicyAsync()
    {
        await Browser.Default.OpenAsync("https://gfmm.eu/nopenwrtremote/privacy", BrowserLaunchMode.SystemPreferred);
    }
}
