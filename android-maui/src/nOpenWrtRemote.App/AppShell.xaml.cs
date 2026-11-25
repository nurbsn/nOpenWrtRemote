using nOpenWrtRemote.App.Views;

namespace nOpenWrtRemote.App;

public partial class AppShell : Shell
{
    public AppShell()
    {
        InitializeComponent();
        Routing.RegisterRoute("pair", typeof(PairRouterPage));
        Routing.RegisterRoute("dashboard", typeof(DashboardPage));
        Routing.RegisterRoute("luci", typeof(RemoteLuciPage));
        Routing.RegisterRoute("settings", typeof(SettingsPage));
    }
}
