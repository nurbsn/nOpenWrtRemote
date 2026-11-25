using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using nOpenWrtRemote.App.Services;
using nOpenWrtRemote.Core.Network;
using nOpenWrtRemote.Core.Protocol;

namespace nOpenWrtRemote.App.ViewModels;

[QueryProperty(nameof(IncomingUri), "uri")]
public partial class PairRouterViewModel : ObservableObject
{
    private readonly IdentityService _identity;
    private readonly RouterStoreService _store;

    public PairRouterViewModel(IdentityService identity, RouterStoreService store)
    {
        _identity = identity;
        _store = store;
    }

    [ObservableProperty]
    private string _manualUri = string.Empty;

    [ObservableProperty]
    private string _deviceName = DeviceInfo.Current.Name;

    [ObservableProperty]
    private string _statusMessage = "Zeskanuj kod QR z panelu LuCI (Services → nOpenWrtRemote) lub wklej link parowania.";

    [ObservableProperty]
    private bool _isBusy;

    public string IncomingUri
    {
        set
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                ManualUri = Uri.UnescapeDataString(value);
                _ = PairWithUriAsync(ManualUri);
            }
        }
    }

    [RelayCommand]
    public async Task PairManualAsync()
    {
        await PairWithUriAsync(ManualUri);
    }

    public async Task<bool> PairWithUriAsync(string rawUri)
    {
        if (IsBusy || string.IsNullOrWhiteSpace(rawUri))
            return false;

        IsBusy = true;
        try
        {
            var pairing = PairingUri.Parse(rawUri);
            StatusMessage = $"Wysyłanie zaszyfrowanego żądania Nostr do {pairing.RouterName}...";
            byte[] privKey = await _identity.GetOrCreatePrivateKeyAsync();
            var profile = await TunnelSession.PairAsync(privKey, pairing, DeviceName);
            await _store.UpsertRouterAsync(profile);
            StatusMessage = $"Sparowano pomyślnie z {profile.Name}!";
            await Shell.Current.GoToAsync("..");
            return true;
        }
        catch (Exception ex)
        {
            StatusMessage = $"Błąd parowania: {ex.Message}";
            return false;
        }
        finally
        {
            IsBusy = false;
        }
    }
}
