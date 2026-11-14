using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using AbpGuard.Controllers;
using AbpGuard.Services;

namespace AbpGuard.Tests;

/// <summary>
/// The names Guard writes into cookies, tokens, headers, stored rows and protected data: neutral by default, and every one
/// the host's when it says, so a host that already shipped under its own keeps them through configuration alone.
/// </summary>
public class HostNamesTests
{
    [Fact]
    public void The_defaults_name_no_product()
    {
        GuardOptions options = new();
        Assert.Equal(("guard_session", "guard_csrf", "guard_embedded", "NEXT_LOCALE"),
            (options.Cookies.Session, options.Cookies.Csrf, options.Cookies.Embedded, options.Cookies.Language));
        Assert.Equal(("/signup/verify", "/reset-password", "/emails/verify", "/oauth/consent", "/admin/security"),
            (options.Pages.SignUpVerify, options.Pages.PasswordReset, options.Pages.AddressVerify, options.Pages.Consent, options.Pages.SecurityLog));
        Assert.Equal((GuardOidc.WebClientId, GuardOidc.MobileClientId), (options.Clients.Web, options.Clients.Mobile));
        Assert.Equal(("web", "mobile", "api", "admins", "users"), (options.Clients.Web, options.Clients.Mobile, options.ApiScope, options.AdminsGroupName, options.Seed.UsersGroupName));
        Assert.Equal(["api", "offline_access"], Services.OAuthAgents.GrantedScopes(options.ApiScope, offline: true).ToArray());
        Assert.Equal(["api"], Services.OAuthAgents.GrantedScopes(options.ApiScope, offline: false).ToArray());

        GuardNames names = new();
        Assert.Equal(("X-Guard-Csrf", "guard_pat_", "urn:abpguard:grant-type:second-factor", "AbpGuard.SecondFactor.v1", "api.read"),
            (names.CsrfHeader, names.PersonalTokenPrefix, names.SecondFactorGrantType, names.Purpose("SecondFactor.v1"), names.ReadScope));
        Assert.Equal(("guard_session", "guard_token", "guard_token_tool", "guard_app_", "guard_cs_"),
            (names.SessionClaim, names.TokenClaim, names.TokenToolClaim, names.AppIdPrefix, names.AppSecretPrefix));
        Assert.Equal(("Guard:Forbidden", "Guard:TooManyRequests"), (GuardErrorCodes.Forbidden, GuardErrorCodes.TooManyRequests));
        Assert.Equal("X-Guard-Signature", names.FeedSignatureHeader);
        Assert.Equal(SecurityFeed.SignatureHeader, names.FeedSignatureHeader);
        Assert.Empty(names.FormerFeedSignatureHeaders);
        Assert.Null(names.Former);
    }

    [Fact]
    public void The_feed_signs_under_the_hosts_former_headers_too_with_the_same_value()
    {
        byte[] body = "[{\"id\":1}]"u8.ToArray();
        DateTimeOffset at = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

        Dictionary<string, string> headers = SecurityFeed.Sign("secret", body, at, "X-Guard-Signature", ["X-Shop-Signature", "x-guard-signature", " ", "X-Old-Signature"]);

        Assert.Equal(["X-Guard-Signature", "X-Shop-Signature", "X-Old-Signature"], headers.Keys.ToArray());
        Assert.All(headers.Values, v => Assert.Equal(headers["X-Guard-Signature"], v));
        Assert.Equal(SecurityFeed.Sign("secret", body, at)[SecurityFeed.SignatureHeader], headers["X-Shop-Signature"]);
    }

    [Fact]
    public void A_host_that_shipped_keeps_its_names_by_configuration()
    {
        IConfiguration configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Guard:Cookies:Session"] = "shop_session", ["Guard:Cookies:Csrf"] = "shop_csrf", ["Guard:Cookies:Embedded"] = "shop_embedded",
            ["Guard:Clients:Web"] = "shop-web", ["Guard:Clients:Mobile"] = "shop-mobile", ["Guard:ApiScope"] = "shop.api",
            ["Guard:AdminsGroupName"] = "shop-admins", ["Guard:Seed:UsersGroupName"] = "shop-users",
            ["Guard:Names:SessionClaim"] = "shop_session", ["Guard:Names:ModeClaim"] = "shop_mode", ["Guard:Names:TokenClaim"] = "shop_token",
            ["Guard:Names:TokenAccessClaim"] = "shop_token_access", ["Guard:Names:TokenProjectClaim"] = "shop_token_project", ["Guard:Names:TokenToolClaim"] = "shop_token_tool",
            ["Guard:Names:CsrfHeader"] = "X-Shop-Csrf", ["Guard:Names:CsrfSalt"] = "shop-csrf:", ["Guard:Names:PersonalTokenPrefix"] = "shop_pat_",
            ["Guard:Names:AppIdPrefix"] = "shop_app_", ["Guard:Names:AppSecretPrefix"] = "shop_cs_", ["Guard:Names:AppKindProperty"] = "shop_kind",
            ["Guard:Names:AppAccessProperty"] = "shop_access", ["Guard:Names:ReadScope"] = "shop.read",
            ["Guard:Names:SecondFactorGrantType"] = "urn:shop:grant-type:second-factor", ["Guard:Names:ProtectionPrefix"] = "Shop.Guard",
            ["Guard:Names:ImportedDirectorySalt"] = "shop-imported-directory:", ["Guard:Names:FeedSignatureHeader"] = "X-Shop-Signature",
            ["Guard:Names:FormerFeedSignatureHeaders:0"] = "X-Old-Signature",
            ["Guard:Names:Former:TokenClaim"] = "old_token", ["Guard:Names:Former:Scopes:old.api"] = "shop.api",
            ["Guard:Pages:SecurityLog"] = "/{lang}/admin/security-log",
        }).Build();
        GuardOptions options = new();
        configuration.GetSection(GuardOptions.Section).Bind(options);
        GuardNames names = new();
        configuration.GetSection(GuardNames.Section).Bind(names);

        Assert.Equal(("shop_session", "shop_csrf", "shop_embedded"), (options.Cookies.Session, options.Cookies.Csrf, options.Cookies.Embedded));
        Assert.Equal(("shop-web", "shop-mobile", "shop.api", "shop-admins", "shop-users"),
            (options.Clients.Web, options.Clients.Mobile, options.ApiScope, options.AdminsGroupName, options.Seed.UsersGroupName));
        Assert.Equal(("shop_session", "shop_mode", "shop_token", "shop_token_access", "shop_token_project", "shop_token_tool"),
            (names.SessionClaim, names.ModeClaim, names.TokenClaim, names.TokenAccessClaim, names.TokenProjectClaim, names.TokenToolClaim));
        Assert.Equal(("X-Shop-Csrf", "shop-csrf:", "shop_app_", "shop_cs_", "shop_kind", "shop_access", "shop.read"),
            (names.CsrfHeader, names.CsrfSalt, names.AppIdPrefix, names.AppSecretPrefix, names.AppKindProperty, names.AppAccessProperty, names.ReadScope));
        Assert.Equal(("urn:shop:grant-type:second-factor", "Shop.Guard.SecondFactor.v1", "shop-imported-directory:"),
            (names.SecondFactorGrantType, names.Purpose("SecondFactor.v1"), names.ImportedDirectorySalt));
        Assert.True(names.IsPersonalToken("shop_pat_abc"));
        Assert.False(names.IsPersonalToken("guard_pat_abc"));
        Assert.Equal(("X-Shop-Signature", "/{lang}/admin/security-log"), (names.FeedSignatureHeader, options.Pages.SecurityLog));
        Assert.Equal(("old_token", "shop.api"), (names.Former?.TokenClaim, names.Former?.Scopes["old.api"]));
        Assert.True(SecurityFeed.Sign("secret", [], header: names.FeedSignatureHeader).ContainsKey("X-Shop-Signature"));
        Assert.Equal(["X-Old-Signature"], names.FormerFeedSignatureHeaders);
        Assert.Equal(["X-Shop-Signature", "X-Old-Signature"],
            SecurityFeed.Sign("secret", [], header: names.FeedSignatureHeader, alsoUnder: names.FormerFeedSignatureHeaders).Keys.ToArray());
    }

    [Fact]
    public void A_session_is_read_and_issued_under_the_hosts_cookie_names()
    {
        ServiceProvider services = new ServiceCollection().Configure<GuardOptions>(o => { o.Cookies.Session = "shop_session"; o.Cookies.Csrf = "shop_csrf"; })
            .BuildServiceProvider();
        DefaultHttpContext http = new() { RequestServices = services };
        http.Request.Headers.Cookie = "shop_session=abc";

        Assert.True(WebSessionHandler.Carries(http.Request));
        WebSessionHandler.Issue(http, "secret", embedded: false);
        string[] set = [.. http.Response.Headers.SetCookie.Select(c => c!)];
        Assert.Contains(set, c => c.StartsWith("shop_session=", StringComparison.Ordinal));
        Assert.Contains(set, c => c.StartsWith("shop_csrf=", StringComparison.Ordinal));
        Assert.DoesNotContain(set, c => c.StartsWith("guard_session=", StringComparison.Ordinal));
    }
}
