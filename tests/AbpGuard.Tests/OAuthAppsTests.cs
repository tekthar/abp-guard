using AbpGuard.Services;
using Volo.Abp;

namespace AbpGuard.Tests;

/// <summary>Where an app may send people back (M7, RFC 8252): https, http to this computer only, or the app's own scheme.</summary>
public class OAuthAppsTests
{
    [Theory]
    [InlineData("https://claude.ai/api/mcp/auth_callback")]
    [InlineData("http://127.0.0.1:53123/callback")]
    [InlineData("http://localhost:6274/oauth/callback")]
    [InlineData("http://[::1]:8080/cb")]
    [InlineData("cursor://anysphere.cursor-retrieval/oauth/callback")]
    [InlineData("com.example.app:/oauth2redirect")]
    public void An_address_an_app_may_use(string uri) => Assert.Single(OAuthApps.RedirectUris([uri]));

    [Theory]
    [InlineData("http://evil.example/cb")]
    [InlineData("javascript:alert(1)")]
    [InlineData("data:text/html,hi")]
    [InlineData("file:///etc/passwd")]
    [InlineData("https://app.example/cb#token")]
    [InlineData("/relative/cb")]
    public void An_address_an_app_may_not_use(string uri) =>
        Assert.Equal("invalid_client_metadata", Assert.Throws<BusinessException>(() => OAuthApps.RedirectUris([uri])).Code);

    [Fact]
    public void One_to_ten_addresses()
    {
        Assert.Throws<BusinessException>(() => OAuthApps.RedirectUris([]));
        Assert.Throws<BusinessException>(() => OAuthApps.RedirectUris(Enumerable.Range(1, 11).Select(i => $"https://app.example/cb{i}")));
        Assert.Single(OAuthApps.RedirectUris(["https://app.example/cb", " https://app.example/cb "]));
    }
}
