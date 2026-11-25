using System.Text.Json;
using nOpenWrtRemote.Core.Models;
using nOpenWrtRemote.Core.Protocol;

namespace nOpenWrtRemote.App.Services;

public sealed class RouterStoreService
{
    private const string RoutersKey = "nort_routers_json_v1";
    private const string BiometricKey = "nort_biometric_enabled";
    private const string DefaultRelayKey = "nort_default_relay";

    public async Task<List<RouterProfile>> LoadRoutersAsync()
    {
        string? json = await SecureStorage.Default.GetAsync(RoutersKey);
        if (string.IsNullOrWhiteSpace(json))
            return [];
        return JsonSerializer.Deserialize<List<RouterProfile>>(json) ?? [];
    }

    public async Task SaveRoutersAsync(List<RouterProfile> routers)
    {
        string json = JsonSerializer.Serialize(routers);
        await SecureStorage.Default.SetAsync(RoutersKey, json);
    }

    public async Task UpsertRouterAsync(RouterProfile profile)
    {
        var list = await LoadRoutersAsync();
        int idx = list.FindIndex(r => string.Equals(r.RouterPubHex, profile.RouterPubHex, StringComparison.OrdinalIgnoreCase));
        if (idx >= 0)
            list[idx] = profile;
        else
            list.Add(profile);
        await SaveRoutersAsync(list);
    }

    public async Task RemoveRouterAsync(string routerId)
    {
        var list = await LoadRoutersAsync();
        list.RemoveAll(r => r.Id == routerId);
        await SaveRoutersAsync(list);
    }

    public bool BiometricEnabled
    {
        get => Preferences.Default.Get(BiometricKey, false);
        set => Preferences.Default.Set(BiometricKey, value);
    }

    public string DefaultRelay
    {
        get => Preferences.Default.Get(DefaultRelayKey, NortConstants.DefaultRelay);
        set => Preferences.Default.Set(DefaultRelayKey, string.IsNullOrWhiteSpace(value) ? NortConstants.DefaultRelay : value.Trim());
    }
}
