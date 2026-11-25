#if ANDROID
using AndroidX.Biometric;
using AndroidX.Core.Content;
using AndroidX.Fragment.App;
#endif

namespace nOpenWrtRemote.App.Services;

public sealed class BiometricAuthService
{
    public Task<bool> AuthenticateAsync(string title, string subtitle)
    {
#if ANDROID
        var activity = Platform.CurrentActivity as FragmentActivity;
        if (activity is null)
            return Task.FromResult(true);

        var manager = BiometricManager.From(activity);
        int authenticators = BiometricManager.Authenticators.BiometricWeak |
                             BiometricManager.Authenticators.DeviceCredential;
        if (manager.CanAuthenticate(authenticators) != BiometricManager.BiometricSuccess)
            return Task.FromResult(true);

        var tcs = new TaskCompletionSource<bool>();
        var executor = ContextCompat.GetMainExecutor(activity);
        var callback = new AuthCallback(tcs);
        var prompt = new BiometricPrompt(activity, executor, callback);
        var info = new BiometricPrompt.PromptInfo.Builder()
            .SetTitle(title)
            .SetSubtitle(subtitle)
            .SetAllowedAuthenticators(authenticators)
            .Build();

        MainThread.BeginInvokeOnMainThread(() => prompt.Authenticate(info));
        return tcs.Task;
#else
        return Task.FromResult(true);
#endif
    }

#if ANDROID
    private sealed class AuthCallback(TaskCompletionSource<bool> tcs) : BiometricPrompt.AuthenticationCallback
    {
        public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result)
            => tcs.TrySetResult(true);

        public override void OnAuthenticationError(int errorCode, Java.Lang.ICharSequence errString)
            => tcs.TrySetResult(false);

        public override void OnAuthenticationFailed()
        {
            // Let user retry until cancelled or succeeded
        }
    }
#endif
}
