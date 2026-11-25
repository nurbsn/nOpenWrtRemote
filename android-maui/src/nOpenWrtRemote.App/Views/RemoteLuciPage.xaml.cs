using nOpenWrtRemote.App.ViewModels;

namespace nOpenWrtRemote.App.Views;

public partial class RemoteLuciPage : ContentPage
{
    private readonly RemoteLuciViewModel _vm;

    public RemoteLuciPage(RemoteLuciViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        BindingContext = vm;
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        _vm.RefreshState();
        LuciWebView.Source = _vm.EntryUrl;
    }

    private void OnReloadClicked(object? sender, EventArgs e)
    {
        _vm.RefreshState();
        LuciWebView.Reload();
    }

    private void OnWebViewNavigating(object? sender, WebNavigatingEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(e.Url) || e.Url == "about:blank")
            return;

        // Strictly block navigation outside our local 127.0.0.1 loopback proxy port
        if (!e.Url.StartsWith(_vm.AllowedBaseUrl, StringComparison.OrdinalIgnoreCase))
        {
            e.Cancel = true;
        }
    }
}
