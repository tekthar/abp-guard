using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Npgsql;
using AbpGuard.Services.TwoFactor;

namespace AbpGuard.Host.Tests;

/// <summary>
/// A site that shipped under names of its own keeps them by configuration: after a restart its browsers stay signed in,
/// its personal access tokens still sign in, and the authenticator apps' secrets it protected still read. The same site
/// started on Guard's defaults recognises none of them, which is why a host moving to AbpGuard sets its names first.
/// Needs Postgres: localhost:5432 (postgres/postgres), or the server GUARD_TEST_POSTGRES names.
/// </summary>
[Collection(SampleHost.Collection)]
public sealed class HostNamesTests : IAsyncLifetime
{
    private static readonly string Server =
        Environment.GetEnvironmentVariable("GUARD_TEST_POSTGRES") is { Length: > 0 } server ? server : "Host=localhost;Port=5432;Username=postgres;Password=postgres";
    private const string AdminPassword = "Host-Admin-Pass-1";

    /// <summary>The site's own names, as a host that already shipped would set them.</summary>
    private static readonly Dictionary<string, string> Names = new()
    {
        ["Guard__Cookies__Session"] = "shop_session",
        ["Guard__Cookies__Csrf"] = "shop_csrf",
        ["Guard__Cookies__Embedded"] = "shop_embedded",
        ["Guard__Names__SessionClaim"] = "shop_session",
        ["Guard__Names__TokenClaim"] = "shop_token",
        ["Guard__Names__CsrfHeader"] = "X-Shop-Csrf",
        ["Guard__Names__CsrfSalt"] = "shop-csrf:",
        ["Guard__Names__PersonalTokenPrefix"] = "shop_pat_",
        ["Guard__Names__ProtectionPrefix"] = "Shop.Guard",
    };

    private readonly string _database = "guard_names_" + Guid.NewGuid().ToString("N")[..12];
    private WebApplicationFactory<Program>? _factory;

    public Task InitializeAsync()
    {
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");
        Environment.SetEnvironmentVariable("ConnectionStrings__Guard", $"{Server};Database={_database}");
        Environment.SetEnvironmentVariable("Guard__Seed__AdminPassword", AdminPassword);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await StopAsync();
        SetNames(on: false);
        NpgsqlConnection.ClearAllPools();
        await using NpgsqlConnection connection = new($"{Server};Database=postgres");
        await connection.OpenAsync();
        await using NpgsqlCommand drop = new($"DROP DATABASE IF EXISTS \"{_database}\" WITH (FORCE)", connection);
        await drop.ExecuteNonQueryAsync();
    }

    [Fact]
    public async Task A_restart_with_the_sites_names_keeps_sessions_tokens_and_secrets()
    {
        // First start: a browser signs in, makes a token, and sets up an authenticator app.
        Start(withNames: true);
        HttpClient browser = Client();
        HttpResponseMessage signedIn = await browser.PostAsJsonAsync("/api/guard/session", new { username = "admin", password = AdminPassword });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        string session = Cookie(signedIn, "shop_session");
        string csrf = Cookie(signedIn, "shop_csrf");
        Assert.DoesNotContain(signedIn.Headers.GetValues("Set-Cookie"), c => c.StartsWith("guard_", StringComparison.Ordinal));
        browser.DefaultRequestHeaders.Add("Cookie", $"shop_session={Uri.EscapeDataString(session)}; shop_csrf={Uri.EscapeDataString(csrf)}");

        JsonElement token = await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/me/tokens", new { name = "script", access = "read", days = 30 });
        string secret = token.GetProperty("secret").GetString()!;
        Assert.StartsWith("shop_pat_", secret, StringComparison.Ordinal);

        JsonElement app = await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/me/second-factors/app");
        byte[] totp = Totp.FromBase32(app.GetProperty("secret").GetString()!);
        long step = Totp.StepAt(DateTimeOffset.UtcNow);
        await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/me/second-factors/app/confirm", new { code = Totp.Code(totp, step) });

        // The same site, started again with its names.
        await StopAsync();
        Start(withNames: true);
        Assert.Equal(HttpStatusCode.OK, (await WithCookieAsync("shop_session", session)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await WithBearerAsync(secret)).StatusCode);
        HttpResponseMessage asked = await Client().PostAsJsonAsync("/api/guard/session", new { username = "admin", password = AdminPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, asked.StatusCode);
        string ticket = JsonDocument.Parse(await asked.Content.ReadAsStringAsync()).RootElement.GetProperty("secondFactor").GetProperty("ticket").GetString()!;
        HttpResponseMessage passed = await Client().PostAsJsonAsync("/api/guard/session/second-factor", new { ticket, method = "app", code = Totp.Code(totp, step + 1) });
        Assert.Equal(HttpStatusCode.OK, passed.StatusCode);

        // Started on Guard's defaults instead, the same site recognises neither.
        await StopAsync();
        Start(withNames: false);
        Assert.Equal(HttpStatusCode.Unauthorized, (await WithCookieAsync("shop_session", session)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await WithBearerAsync(secret)).StatusCode);
    }

    private void Start(bool withNames)
    {
        SetNames(withNames);
        _factory = new WebApplicationFactory<Program>();
    }

    private async Task StopAsync()
    {
        if (_factory is not null)
        {
            await _factory.DisposeAsync();
            _factory = null;
        }
    }

    private static void SetNames(bool on)
    {
        foreach ((string key, string value) in Names)
        {
            Environment.SetEnvironmentVariable(key, on ? value : null);
        }
    }

    private HttpClient Client() => _factory!.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, AllowAutoRedirect = false });

    private static string Cookie(HttpResponseMessage response, string name) =>
        Uri.UnescapeDataString(response.Headers.GetValues("Set-Cookie").First(c => c.StartsWith(name + "=", StringComparison.Ordinal))[(name.Length + 1)..].Split(';')[0]);

    private static async Task<JsonElement> SendAsync(HttpClient client, string csrf, HttpMethod method, string url, object? body = null)
    {
        using HttpRequestMessage request = new(method, url) { Content = body is null ? null : JsonContent.Create(body) };
        request.Headers.Add("X-Shop-Csrf", csrf);
        HttpResponseMessage response = await client.SendAsync(request);
        string text = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"{method} {url}: {(int)response.StatusCode} {text}");
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    private async Task<HttpResponseMessage> WithCookieAsync(string name, string value)
    {
        using HttpRequestMessage request = new(HttpMethod.Get, "/api/guard/me");
        request.Headers.Add("Cookie", $"{name}={Uri.EscapeDataString(value)}");
        return await Client().SendAsync(request);
    }

    private async Task<HttpResponseMessage> WithBearerAsync(string token)
    {
        using HttpRequestMessage request = new(HttpMethod.Get, "/api/guard/me");
        request.Headers.Authorization = new("Bearer", token);
        return await Client().SendAsync(request);
    }
}
