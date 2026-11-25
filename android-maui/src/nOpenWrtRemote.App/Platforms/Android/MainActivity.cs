using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using nOpenWrtRemote.App.Services;

namespace nOpenWrtRemote.App;

[Activity(
    Theme = "@style/Maui.SplashTheme",
    MainLauncher = true,
    LaunchMode = LaunchMode.SingleTop,
    ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
[IntentFilter(
    [Intent.ActionView],
    Categories = [Intent.CategoryDefault, Intent.CategoryBrowsable],
    DataScheme = "nopenwrt",
    DataHost = "pair")]
public class MainActivity : MauiAppCompatActivity
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        HandleDeepLink(Intent);
    }

    protected override void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);
        HandleDeepLink(intent);
    }

    private static void HandleDeepLink(Intent? intent)
    {
        string? data = intent?.DataString;
        if (!string.IsNullOrWhiteSpace(data) && data.StartsWith("nopenwrt://pair", StringComparison.OrdinalIgnoreCase))
        {
            DeepLinkInbox.SetPendingPairUri(data);
        }
    }
}
