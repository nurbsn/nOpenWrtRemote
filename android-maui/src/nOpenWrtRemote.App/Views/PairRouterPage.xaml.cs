using ZXing.Net.Maui;
using nOpenWrtRemote.App.ViewModels;

namespace nOpenWrtRemote.App.Views;

public partial class PairRouterPage : ContentPage
{
    private readonly PairRouterViewModel _vm;
    private bool _handledQr;

    public PairRouterPage(PairRouterViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        BindingContext = vm;
        BarcodeReader.Options = new BarcodeReaderOptions
        {
            Formats = BarcodeFormat.QrCode,
            AutoRotate = true,
            Multiple = false,
            TryHarder = true,
            TryInverted = true
        };
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        _handledQr = false;
        var status = await Permissions.RequestAsync<Permissions.Camera>();
        if (status != PermissionStatus.Granted)
        {
            BarcodeReader.IsDetecting = false;
            _vm.StatusMessage = "Brak uprawnień do aparatu — możesz wkleić link parowania poniżej.";
        }
        else
        {
            BarcodeReader.IsDetecting = false;
            BarcodeReader.IsDetecting = true;
        }
    }

    protected override void OnDisappearing()
    {
        BarcodeReader.IsDetecting = false;
        base.OnDisappearing();
    }

    private void OnBarcodesDetected(object? sender, BarcodeDetectionEventArgs e)
    {
        if (_handledQr) return;
        string? raw = e.Results?.FirstOrDefault()?.Value;
        if (string.IsNullOrWhiteSpace(raw))
            return;

        if (!raw.StartsWith("nopenwrt://pair", StringComparison.OrdinalIgnoreCase))
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                _vm.StatusMessage = "Wykryto inny kod QR (nie jest to kod parowania nOpenWrtRemote).";
            });
            return;
        }

        _handledQr = true;
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            BarcodeReader.IsDetecting = false;
            _vm.ManualUri = raw;
            bool ok = await _vm.PairWithUriAsync(raw);
            if (!ok)
            {
                _handledQr = false;
                BarcodeReader.IsDetecting = true;
            }
        });
    }
}
