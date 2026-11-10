using Microsoft.AspNetCore.Http;
using AbpGuard.Services;

namespace AbpGuard.Tests;

/// <summary>
/// The web's session cookie: which scheme signs a request in, the anti-forgery value tied to each session, and
/// sign-ins refused when they come from another site.
/// </summary>
public class WebSessionTests
{
    private const string Secret = "k3y-0f-a-s3ss10n_with-enough-random-in-it-xyz";
    private static readonly GuardNames Names = new();

    [Fact]
    public void A_bearer_token_wins_over_the_cookie()
    {
        Assert.Equal(PersonalTokenHandler.SchemeName, AbpGuardModule.SchemeFor(Request(authorization: "Bearer " + Names.PersonalTokenPrefix + "abc", cookie: Secret)));
        Assert.Equal("OpenIddict.Validation.AspNetCore", AbpGuardModule.SchemeFor(Request(authorization: "Bearer eyJhbGciOi", cookie: Secret)));
    }

    [Fact]
    public void A_request_with_only_the_cookie_is_the_sessions()
    {
        Assert.Equal(WebSessionHandler.SchemeName, AbpGuardModule.SchemeFor(Request(cookie: Secret)));
        Assert.Equal("OpenIddict.Validation.AspNetCore", AbpGuardModule.SchemeFor(Request()));
    }

    [Fact]
    public void The_anti_forgery_value_belongs_to_one_session()
    {
        string csrf = WebSessions.CsrfFor(Secret, Names);
        Assert.Equal(csrf, WebSessions.CsrfFor(Secret, Names));
        Assert.NotEqual(csrf, WebSessions.CsrfFor(Secret + "x", Names));
        Assert.NotEqual(WebSessions.Hash(Secret), csrf);
        Assert.DoesNotContain(Secret, csrf, StringComparison.Ordinal);

        Assert.True(WebSessions.CsrfMatches(Secret, csrf, Names));
        Assert.False(WebSessions.CsrfMatches(Secret, WebSessions.CsrfFor("another session", Names), Names));
        Assert.False(WebSessions.CsrfMatches(Secret, "", Names));
        Assert.False(WebSessions.CsrfMatches(Secret, null, Names));
    }

    [Theory]
    [InlineData("same-origin", null, false)]
    [InlineData("same-site", null, true)]
    [InlineData("cross-site", null, true)]
    [InlineData(null, "http://site.test", false)]
    [InlineData(null, "http://evil.test", true)]
    [InlineData(null, "https://site.example.com", false)]
    [InlineData(null, null, false)]
    public void A_sign_in_from_another_site_is_refused(string? fetchSite, string? origin, bool refused)
    {
        HttpRequest request = Request(method: "POST");
        if (fetchSite is not null)
        {
            request.Headers["Sec-Fetch-Site"] = fetchSite;
        }

        if (origin is not null)
        {
            request.Headers.Origin = origin;
        }

        Assert.Equal(refused, WebSessionHandler.IsCrossSite(request, "https://site.example.com"));
    }

    [Fact]
    public void Reading_is_never_cross_site_and_a_proxy_says_https()
    {
        HttpRequest get = Request();
        get.Headers.Origin = "http://evil.test";
        Assert.False(WebSessionHandler.IsCrossSite(get, null));

        HttpRequest proxied = Request(method: "POST");
        proxied.Headers["X-Forwarded-Proto"] = "https";
        proxied.Headers.Origin = "https://site.test";
        Assert.False(WebSessionHandler.IsCrossSite(proxied, null));
        proxied.Headers.Origin = "http://site.test";
        Assert.True(WebSessionHandler.IsCrossSite(proxied, null));
    }

    [Fact]
    public void The_cookies_are_set_and_cleared_together()
    {
        DefaultHttpContext http = new();
        http.Request.Host = new HostString("site.test");
        WebSessionHandler.Issue(http, Secret);
        string[] set = http.Response.Headers.SetCookie.ToArray()!;
        string session = Assert.Single(set, c => c.StartsWith(new GuardCookieOptions().Session + "=", StringComparison.Ordinal));
        string csrf = Assert.Single(set, c => c.StartsWith(new GuardCookieOptions().Csrf + "=", StringComparison.Ordinal));
        Assert.Contains("httponly", session, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", session, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("httponly", csrf, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(WebSessions.CsrfFor(Secret, Names), csrf, StringComparison.Ordinal);
        Assert.DoesNotContain("secure", session, StringComparison.OrdinalIgnoreCase);

        DefaultHttpContext https = new();
        https.Request.Scheme = "https";
        WebSessionHandler.Issue(https, Secret);
        Assert.All(https.Response.Headers.SetCookie.ToArray(), c => Assert.Contains("secure", c!, StringComparison.OrdinalIgnoreCase));

        // TLS ended at the ingress: the gateway passes on the ingress's X-Forwarded-Proto.
        DefaultHttpContext proxied = new();
        proxied.Request.Headers["X-Forwarded-Proto"] = "https";
        WebSessionHandler.Issue(proxied, Secret);
        Assert.All(proxied.Response.Headers.SetCookie.ToArray(), c => Assert.Contains("secure", c!, StringComparison.OrdinalIgnoreCase));

        DefaultHttpContext cleared = new();
        WebSessionHandler.Clear(cleared);
        Assert.Equal(3, cleared.Response.Headers.SetCookie.Count);
        Assert.All(cleared.Response.Headers.SetCookie.ToArray(), c => Assert.Contains("expires=Thu, 01 Jan 1970", c!, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void A_handoff_marks_the_browser_embedded_and_a_sign_in_unmarks_it()
    {
        static string? Embedded(DefaultHttpContext http) =>
            http.Response.Headers.SetCookie.ToArray().FirstOrDefault(c => c!.StartsWith(new GuardCookieOptions().Embedded + "=", StringComparison.Ordinal));

        DefaultHttpContext handoff = new();
        WebSessionHandler.Issue(handoff, Secret, embedded: true);
        Assert.StartsWith(new GuardCookieOptions().Embedded + "=1;", Embedded(handoff));

        DefaultHttpContext signIn = new();
        signIn.Request.Headers.Cookie = $"{new GuardCookieOptions().Embedded}=1";
        WebSessionHandler.Issue(signIn, Secret, embedded: false);
        Assert.Contains("expires=Thu, 01 Jan 1970", Embedded(signIn), StringComparison.OrdinalIgnoreCase);

        DefaultHttpContext slid = new();
        slid.Request.Headers.Cookie = $"{new GuardCookieOptions().Embedded}=1";
        WebSessionHandler.Issue(slid, Secret);
        Assert.StartsWith(new GuardCookieOptions().Embedded + "=1;", Embedded(slid));
        DefaultHttpContext plain = new();
        WebSessionHandler.Issue(plain, Secret);
        Assert.Null(Embedded(plain));
    }

    [Theory]
    [InlineData("/browse/PAY-4?tab=history", "/browse/PAY-4?tab=history")]
    [InlineData("/apps/test-management/cases", "/apps/test-management/cases")]
    [InlineData("//evil.example/x", "/")]
    [InlineData("/\\evil.example", "/")]
    [InlineData("https://evil.example/", "/")]
    [InlineData("javascript:alert(1)", "/")]
    [InlineData("/ok\r\nSet-Cookie: x=1", "/")]
    [InlineData("", "/")]
    [InlineData(null, "/")]
    public void A_web_view_goes_on_only_to_a_page_of_the_site(string? next, string expected) =>
        Assert.Equal(expected, AbpGuard.Controllers.SessionController.SafeNext(next));

    private static HttpRequest Request(string method = "GET", string? authorization = null, string? cookie = null)
    {
        DefaultHttpContext http = new();
        http.Request.Method = method;
        http.Request.Scheme = "http";
        http.Request.Host = new HostString("site.test");
        if (authorization is not null)
        {
            http.Request.Headers.Authorization = authorization;
        }

        if (cookie is not null)
        {
            http.Request.Headers.Cookie = $"{new GuardCookieOptions().Session}={cookie}";
        }

        return http.Request;
    }
}
