namespace AbpGuard.Controllers;

/// <summary>Guard's first-party OpenIddict names: the API's scope and the web and mobile clients.</summary>
public static class GuardOidc
{
    /// <summary>The scope every call to the host's API needs: <see cref="GuardOptions.ApiScope"/>'s default.</summary>
    public const string ApiScope = "api";

    /// <summary>The first-party Next.js server (a confidential client).</summary>
    public const string WebClientId = "web";

    /// <summary>
    /// The first-party mobile app: a public client, since an app on a phone can't keep a secret; it signs in
    /// with the person's password and keeps the session with refresh tokens, like the web, but can't ask for a step-up.
    /// </summary>
    public const string MobileClientId = "mobile";
}
