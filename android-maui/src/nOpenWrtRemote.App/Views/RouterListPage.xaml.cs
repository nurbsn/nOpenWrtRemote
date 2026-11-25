using nOpenWrtRemote.App.ViewModels;

namespace nOpenWrtRemote.App.Views;

public partial class RouterListPage : ContentPage
{
    private readonly RouterListViewModel _vm;

    public RouterListPage(RouterListViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        BindingContext = vm;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        await _vm.InitializeAsync();
    }
}
