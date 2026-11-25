using ZXing.Net.Maui.Controls;
using nOpenWrtRemote.App.Services;
using nOpenWrtRemote.App.ViewModels;
using nOpenWrtRemote.App.Views;

namespace nOpenWrtRemote.App;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder
            .UseMauiApp<App>()
            .UseBarcodeReader();

        builder.Services.AddSingleton<IdentityService>();
        builder.Services.AddSingleton<RouterStoreService>();
        builder.Services.AddSingleton<ConnectionManager>();
        builder.Services.AddSingleton<BiometricAuthService>();

        builder.Services.AddTransient<RouterListViewModel>();
        builder.Services.AddTransient<PairRouterViewModel>();
        builder.Services.AddTransient<DashboardViewModel>();
        builder.Services.AddTransient<RemoteLuciViewModel>();
        builder.Services.AddTransient<SettingsViewModel>();

        builder.Services.AddTransient<RouterListPage>();
        builder.Services.AddTransient<PairRouterPage>();
        builder.Services.AddTransient<DashboardPage>();
        builder.Services.AddTransient<RemoteLuciPage>();
        builder.Services.AddTransient<SettingsPage>();

        return builder.Build();
    }
}
