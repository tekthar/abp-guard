using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OpenIddict.Abstractions;
using AbpGuard.Services.TwoFactor;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AbpGuard.Host.Tests;

/// <summary>
/// Step-up by category through the sample host, with Guard's default levels: a strong category (security, roles) takes a
/// passkey alone or the password and the app, never the password alone or with a sent or recovery code, and tells someone
/// with no strong factor to set one up; adding a factor is strong once the person has one, where a sign-in with a recovery
/// code counts; a site admin's token is strong; every factor added or removed is told to the person; a token from the
/// phone's second step with the app is strong too. The app's code alone steps up strongly unless the operator sets
/// Guard:StepUp:AppCodeAlone to false, and too many wrong codes then end the session.
/// Needs Postgres: localhost:5432 (postgres/postgres), or the server GUARD_TEST_POSTGRES names.
/// </summary>
[Collection(SampleHost.Collection)]
public sealed class StrongStepUpTests : IAsyncLifetime
{
    private static readonly string Server =
        Environment.GetEnvironmentVariable("GUARD_TEST_POSTGRES") is { Length: > 0 } server ? server : "Host=localhost;Port=5432;Username=postgres;Password=postgres";
    private const string AdminPassword = "Host-Admin-Pass-1";
    private const string Password = "Strong-Pass-12345";
    private static readonly string CsrfHeader = new GuardNames().CsrfHeader;

    private readonly string _database = "guard_strong_" + Guid.NewGuid().ToString("N")[..12];
    private readonly string _mail = Path.Combine(Path.GetTempPath(), "guard-strong-mail-" + Guid.NewGuid().ToString("N"));
    private WebApplicationFactory<Program>? _factory;

    public Task InitializeAsync()
    {
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");
        Environment.SetEnvironmentVariable("ConnectionStrings__Guard", $"{Server};Database={_database}");
        Environment.SetEnvironmentVariable("Guard__Seed__AdminPassword", AdminPassword);
        Environment.SetEnvironmentVariable("Guard__Messenger__PickupFolder", _mail);
        // The default strong categories but `accounts`, so the set-up's admin, with no factor yet, makes its people.
        Environment.SetEnvironmentVariable("Guard__StepUp__Strong", "plugins,roles,security,directories,apps,service-accounts,admin-tokens,exports,backups,scripts,secrets,sites");
        _factory = new WebApplicationFactory<Program>();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        if (_factory is not null)
        {
            await _factory.DisposeAsync();
        }

        NpgsqlConnection.ClearAllPools();
        await using NpgsqlConnection connection = new($"{Server};Database=postgres");
        await connection.OpenAsync();
        await using NpgsqlCommand drop = new($"DROP DATABASE IF EXISTS \"{_database}\" WITH (FORCE)", connection);
        await drop.ExecuteNonQueryAsync();
        if (Directory.Exists(_mail))
        {
            Directory.Delete(_mail, recursive: true);
        }

        Environment.SetEnvironmentVariable("Guard__StepUp__AppCodeAlone", null);
    }

    [Fact]
    public async Task A_strong_category_takes_the_password_and_the_app_and_never_the_password_alone()
    {
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);
        object settings = new { retentionDays = 400, stepUpMinutes = 10 };

        // No strong factor yet: the security settings say to set one up; a password-level category passes on the sign-in.
        using (JsonDocument refused = await ErrorAsync(await SendAsync(admin, csrf, HttpMethod.Put, "/api/guard/security/settings", settings), HttpStatusCode.Forbidden, "strong_factor_required"))
        {
            Assert.Equal("security", refused.RootElement.GetProperty("error").GetProperty("data").GetProperty("category").GetString());
        }

        Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/accounts",
            new { username = "sam", displayName = "Sam", email = "sam@example.test", password = Password })).StatusCode);

        // The first factor takes the password's sign-in; then the password alone isn't enough, and the 403 says how to pass.
        byte[] secret = await SetUpAppAsync(admin, csrf);
        using (JsonDocument asked = await ErrorAsync(await SendAsync(admin, csrf, HttpMethod.Put, "/api/guard/security/settings", settings), HttpStatusCode.Forbidden, "step_up_required"))
        {
            JsonElement data = asked.RootElement.GetProperty("error").GetProperty("data");
            Assert.Equal("strong", data.GetProperty("level").GetString());
            Assert.Equal("security", data.GetProperty("category").GetString());
            Assert.Equal(["app"], data.GetProperty("methods").EnumerateArray().Select(m => m.GetString()!).ToArray());
            Assert.True(data.GetProperty("appCodeAlone").GetBoolean());
            Assert.Equal(600, data.GetProperty("maxAgeSeconds").GetInt32());
        }

        // A recovery code with the password is a step-up, but not a strong one.
        string recovery = await FirstRecoveryCodeAsync(admin, csrf);
        using (JsonDocument weak = JsonDocument.Parse(await (await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/session/step-up",
                   new { password = AdminPassword, method = "recovery", code = recovery })).Content.ReadAsStringAsync()))
        {
            Assert.Equal(JsonValueKind.Null, weak.RootElement.GetProperty("strongAuthTime").ValueKind);
        }

        await ErrorAsync(await SendAsync(admin, csrf, HttpMethod.Put, "/api/guard/security/settings", settings), HttpStatusCode.Forbidden, "step_up_required");

        // The password and the app's code: strong, and the security settings save, saying which categories are strong.
        HttpResponseMessage stepped = await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/session/step-up",
            new { password = AdminPassword, method = "app", code = Totp.Code(secret, Totp.StepAt(DateTimeOffset.UtcNow.AddSeconds(30))) });
        Assert.Equal(HttpStatusCode.OK, stepped.StatusCode);
        using (JsonDocument proof = JsonDocument.Parse(await stepped.Content.ReadAsStringAsync()))
        {
            Assert.Equal(proof.RootElement.GetProperty("authTime").GetDateTime(), proof.RootElement.GetProperty("strongAuthTime").GetDateTime());
        }

        HttpResponseMessage saved = await SendAsync(admin, csrf, HttpMethod.Put, "/api/guard/security/settings", settings);
        Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
        using JsonDocument shown = JsonDocument.Parse(await saved.Content.ReadAsStringAsync());
        string[] strong = [.. shown.RootElement.GetProperty("stepUpStrong").EnumerateArray().Select(c => c.GetString()!)];
        Assert.Contains("security", strong);
        Assert.Contains("roles", strong);
        Assert.DoesNotContain("factors", strong);

        // The site admins' rule is off unless the environment turns it on: no date for anyone.
        Assert.False(shown.RootElement.GetProperty("adminsStrongFactor").GetProperty("required").GetBoolean());
        using JsonDocument me = JsonDocument.Parse(await admin.GetStringAsync("/api/guard/me"));
        JsonElement strongFactor = me.RootElement.GetProperty("strongFactor");
        Assert.True(strongFactor.GetProperty("has").GetBoolean());
        Assert.Equal(["app"], strongFactor.GetProperty("methods").EnumerateArray().Select(m => m.GetString()!).ToArray());
        Assert.Equal(JsonValueKind.Null, strongFactor.GetProperty("requiredBy").ValueKind);
    }

    [Fact]
    public async Task The_apps_code_alone_is_a_strong_step_up_by_default()
    {
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);
        object settings = new { retentionDays = 400, stepUpMinutes = 10 };
        byte[] secret = await SetUpAppAsync(admin, csrf);

        using (JsonDocument asked = await ErrorAsync(await SendAsync(admin, csrf, HttpMethod.Put, "/api/guard/security/settings", settings), HttpStatusCode.Forbidden, "step_up_required"))
        {
            JsonElement error = asked.RootElement.GetProperty("error");
            Assert.True(error.GetProperty("data").GetProperty("appCodeAlone").GetBoolean());
            Assert.Equal("Confirm it's you with your passkey or your authenticator app.", error.GetProperty("message").GetString());
        }

        // No code, then a wrong one: refused, and the session goes on.
        await ErrorAsync(await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/session/step-up", new { method = "app" }), HttpStatusCode.BadRequest, "second_factor_required");
        await ErrorAsync(await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/session/step-up", new { method = "app", code = "000000" }), HttpStatusCode.BadRequest,
            "second_factor_failed");

        // The right code alone: strong, and the strong action passes; the settings say the operator allows it.
        HttpResponseMessage stepped = await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/session/step-up",
            new { method = "app", code = Totp.Code(secret, Totp.StepAt(DateTimeOffset.UtcNow.AddSeconds(30))) });
        Assert.Equal(HttpStatusCode.OK, stepped.StatusCode);
        using (JsonDocument proof = JsonDocument.Parse(await stepped.Content.ReadAsStringAsync()))
        {
            Assert.Equal(proof.RootElement.GetProperty("authTime").GetDateTime(), proof.RootElement.GetProperty("strongAuthTime").GetDateTime());
        }

        HttpResponseMessage saved = await SendAsync(admin, csrf, HttpMethod.Put, "/api/guard/security/settings", settings);
        Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
        using JsonDocument shown = JsonDocument.Parse(await saved.Content.ReadAsStringAsync());
        Assert.True(shown.RootElement.GetProperty("stepUpAppCodeAlone").GetBoolean());
    }

    [Fact]
    public async Task Too_many_wrong_codes_alone_end_the_session()
    {
        await PersonAsync("ana");
        HttpClient browser = Client();
        string csrf = await SignInAsync(browser, "ana", Password);
        await SetUpAppAsync(browser, csrf);

        // Ten wrong codes are refused with the session going on; the next ends it, as too many wrong passwords do.
        for (int i = 0; i < 10; i++)
        {
            await ErrorAsync(await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/session/step-up", new { method = "app", code = "000000" }), HttpStatusCode.BadRequest,
                "second_factor_failed");
        }

        await ErrorAsync(await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/session/step-up", new { method = "app", code = "000000" }), HttpStatusCode.Unauthorized,
            "session_ended");
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/guard/me")).StatusCode);
    }

    [Fact]
    public async Task With_the_apps_code_alone_turned_off_it_needs_the_password_too()
    {
        Environment.SetEnvironmentVariable("Guard__StepUp__AppCodeAlone", "false");
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);
        object settings = new { retentionDays = 400, stepUpMinutes = 10 };
        byte[] secret = await SetUpAppAsync(admin, csrf);

        using (JsonDocument asked = await ErrorAsync(await SendAsync(admin, csrf, HttpMethod.Put, "/api/guard/security/settings", settings), HttpStatusCode.Forbidden, "step_up_required"))
        {
            JsonElement error = asked.RootElement.GetProperty("error");
            Assert.False(error.GetProperty("data").GetProperty("appCodeAlone").GetBoolean());
            Assert.Equal("Confirm it's you with your passkey, or your password and authenticator app.", error.GetProperty("message").GetString());
        }

        string code = Totp.Code(secret, Totp.StepAt(DateTimeOffset.UtcNow.AddSeconds(30)));
        await ErrorAsync(await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/session/step-up", new { method = "app", code }), HttpStatusCode.BadRequest, "invalid_request");
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/session/step-up", new { password = AdminPassword, method = "app", code })).StatusCode);

        HttpResponseMessage saved = await SendAsync(admin, csrf, HttpMethod.Put, "/api/guard/security/settings", settings);
        Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
        using JsonDocument shown = JsonDocument.Parse(await saved.Content.ReadAsStringAsync());
        Assert.False(shown.RootElement.GetProperty("stepUpAppCodeAlone").GetBoolean());
    }

    [Fact]
    public async Task Adding_a_factor_is_strong_once_the_person_has_one_and_a_recovery_codes_sign_in_counts_for_that_alone()
    {
        await PersonAsync("tia");
        HttpClient browser = Client();
        string csrf = await SignInAsync(browser, "tia", Password);
        await SetUpAppAsync(browser, csrf);
        string recovery = await FirstRecoveryCodeAsync(browser, csrf);

        // Another browser signs in with the password and a recovery code, as someone who lost their phone would.
        HttpClient again = Client();
        (string ticket, _) = await TicketAsync(again, "tia");
        HttpResponseMessage recovered = await again.PostAsJsonAsync("/api/guard/session/second-factor", new { ticket, method = "recovery", code = recovery });
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
        string againCsrf = Remember(again, recovered);

        // A sign-in with a recovery code may set up a new factor: the person lost their device.
        using SoftwareAuthenticator phone = new();
        JsonElement created = await OptionsAsync(again, againCsrf, "/api/guard/me/passkeys/options");
        HttpResponseMessage added = await SendAsync(again, againCsrf, HttpMethod.Post, "/api/guard/me/passkeys", new { name = "New phone", credential = phone.Register(created) });
        Assert.Equal(HttpStatusCode.OK, added.StatusCode);

        // That counts for adding alone: the app, now one of two, goes at the password level, but the last strong factor
        // asks for a strong step-up, which a recovery code isn't.
        Guid app = await FactorIdAsync(again, "app");
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(again, againCsrf, HttpMethod.Delete, $"/api/guard/me/second-factors/{app}", new { })).StatusCode);
        Guid passkey = await FactorIdAsync(again, "passkey");
        using (JsonDocument asked = await ErrorAsync(await SendAsync(again, againCsrf, HttpMethod.Delete, $"/api/guard/me/second-factors/{passkey}", new { }),
                   HttpStatusCode.Forbidden, "step_up_required"))
        {
            Assert.Equal("strong", asked.RootElement.GetProperty("error").GetProperty("data").GetProperty("level").GetString());
            Assert.Equal(["passkey"], asked.RootElement.GetProperty("error").GetProperty("data").GetProperty("methods").EnumerateArray().Select(m => m.GetString()!).ToArray());
        }

        // The password session that set up the app: adding another factor now needs a strong step-up.
        using (JsonDocument asked = await ErrorAsync(await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/me/second-factors/app", new { }),
                   HttpStatusCode.Forbidden, "step_up_required"))
        {
            Assert.Equal("factors", asked.RootElement.GetProperty("error").GetProperty("data").GetProperty("category").GetString());
        }

        // Each factor added and removed was told to the person.
        Assert.Equal(2, await MailsAsync("tia@example.test", "guard.second-factor-added"));
        Assert.Equal(1, await MailsAsync("tia@example.test", "guard.second-factor-removed"));
    }

    [Fact]
    public async Task A_site_admins_token_is_strong_and_a_persons_own_isnt()
    {
        await PersonAsync("uma");
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);
        object token = new { name = "ci", access = "read", projectIds = (List<Guid>?)null, days = 30 };
        await ErrorAsync(await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/me/tokens", token), HttpStatusCode.Forbidden, "strong_factor_required");

        HttpClient person = Client();
        string personCsrf = await SignInAsync(person, "uma", Password);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(person, personCsrf, HttpMethod.Post, "/api/guard/me/tokens", token)).StatusCode);
    }

    [Fact]
    public async Task The_phones_second_step_with_the_app_gives_a_strong_token_and_the_password_alone_doesnt()
    {
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);
        byte[] secret = await SetUpAppAsync(admin, csrf);
        await RegisterPhoneAsync();

        HttpResponseMessage asked = await Client().PostAsync("/connect/token", Form(("grant_type", "password"), ("client_id", "mobile"), ("username", "admin"),
            ("password", AdminPassword), ("scope", "api offline_access")));
        string ticket = JsonDocument.Parse(await asked.Content.ReadAsStringAsync()).RootElement.GetProperty("ticket").GetString()!;
        HttpResponseMessage granted = await Client().PostAsync("/connect/token", Form(("grant_type", new GuardNames().SecondFactorGrantType), ("client_id", "mobile"),
            ("ticket", ticket), ("method", "app"), ("code", Totp.Code(secret, Totp.StepAt(DateTimeOffset.UtcNow.AddSeconds(30))))));
        string body = await granted.Content.ReadAsStringAsync();
        Assert.True(granted.IsSuccessStatusCode, body);
        string accessToken = JsonDocument.Parse(body).RootElement.GetProperty("access_token").GetString()!;

        using HttpRequestMessage save = new(HttpMethod.Put, "/api/guard/security/settings") { Content = JsonContent.Create(new { retentionDays = 500, stepUpMinutes = 10 }) };
        save.Headers.Authorization = new("Bearer", accessToken);
        Assert.Equal(HttpStatusCode.OK, (await Client().SendAsync(save)).StatusCode);
    }

    // ---- helpers ----

    private HttpClient Client() => _factory!.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });

    private readonly Dictionary<HttpClient, string> _csrf = [];

    private async Task PersonAsync(string username)
    {
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/accounts",
            new { username, displayName = username, email = $"{username}@example.test", password = Password })).StatusCode);
    }

    private async Task<string> SignInAsync(HttpClient client, string username, string password)
    {
        HttpResponseMessage signedIn = await client.PostAsJsonAsync("/api/guard/session", new { username, password });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        return Remember(client, signedIn);
    }

    /// <summary>The anti-forgery value from a response that set the session's cookies, kept for the client.</summary>
    private string Remember(HttpClient client, HttpResponseMessage response)
    {
        string prefix = new GuardCookieOptions().Csrf + "=";
        string cookie = response.Headers.GetValues("Set-Cookie").First(c => c.StartsWith(prefix, StringComparison.Ordinal));
        return _csrf[client] = Uri.UnescapeDataString(cookie[prefix.Length..].Split(';')[0]);
    }

    private async Task<(string Ticket, string[] Methods)> TicketAsync(HttpClient client, string username)
    {
        HttpResponseMessage asked = await client.PostAsJsonAsync("/api/guard/session", new { username, password = Password });
        Assert.Equal(HttpStatusCode.Unauthorized, asked.StatusCode);
        using JsonDocument body = JsonDocument.Parse(await asked.Content.ReadAsStringAsync());
        JsonElement step = body.RootElement.GetProperty("secondFactor");
        return (step.GetProperty("ticket").GetString()!, step.GetProperty("methods").EnumerateArray().Select(m => m.GetString()!).ToArray());
    }

    /// <summary>Sets up the authenticator app for the session's person: its secret.</summary>
    private static async Task<byte[]> SetUpAppAsync(HttpClient client, string csrf)
    {
        HttpResponseMessage started = await SendAsync(client, csrf, HttpMethod.Post, "/api/guard/me/second-factors/app", new { });
        Assert.Equal(HttpStatusCode.OK, started.StatusCode);
        using JsonDocument app = JsonDocument.Parse(await started.Content.ReadAsStringAsync());
        byte[] secret = Totp.FromBase32(app.RootElement.GetProperty("secret").GetString()!);
        HttpResponseMessage confirmed = await SendAsync(client, csrf, HttpMethod.Post, "/api/guard/me/second-factors/app/confirm",
            new { code = Totp.Code(secret, Totp.StepAt(DateTimeOffset.UtcNow)) });
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
        return secret;
    }

    /// <summary>New recovery codes for the session's person (a password-level step-up, which the sign-in is): the first.</summary>
    private static async Task<string> FirstRecoveryCodeAsync(HttpClient client, string csrf)
    {
        HttpResponseMessage renewed = await SendAsync(client, csrf, HttpMethod.Post, "/api/guard/me/second-factors/recovery-codes", new { });
        Assert.Equal(HttpStatusCode.OK, renewed.StatusCode);
        using JsonDocument codes = JsonDocument.Parse(await renewed.Content.ReadAsStringAsync());
        return codes.RootElement.GetProperty("recoveryCodes")[0].GetString()!;
    }

    private static async Task<Guid> FactorIdAsync(HttpClient client, string kind)
    {
        using JsonDocument mine = JsonDocument.Parse(await client.GetStringAsync("/api/guard/me/second-factors"));
        return mine.RootElement.GetProperty("factors").EnumerateArray().First(f => f.GetProperty("kind").GetString() == kind).GetProperty("id").GetGuid();
    }

    private static async Task<JsonElement> OptionsAsync(HttpClient client, string csrf, string path)
    {
        HttpResponseMessage response = await SendAsync(client, csrf, HttpMethod.Post, path, new { });
        string text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, text);
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, string csrf, HttpMethod method, string path, object body)
    {
        using HttpRequestMessage request = new(method, path) { Content = JsonContent.Create(body) };
        request.Headers.Add(CsrfHeader, csrf);
        return await client.SendAsync(request);
    }

    private static async Task<JsonDocument> ErrorAsync(HttpResponseMessage response, HttpStatusCode status, string code)
    {
        string text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == status, $"{(int)response.StatusCode}: {text}");
        JsonDocument body = JsonDocument.Parse(text);
        Assert.Equal(code, body.RootElement.GetProperty("error").GetProperty("code").GetString());
        return body;
    }

    /// <summary>The mails of a kind to an address in the pickup folder.</summary>
    private async Task<int> MailsAsync(string address, string kind)
    {
        int count = 0;
        foreach (string file in Directory.Exists(_mail) ? Directory.GetFiles(_mail, "*.eml") : [])
        {
            string mail = await File.ReadAllTextAsync(file);
            if (mail.Contains($"<{address}>", StringComparison.Ordinal) && mail.Contains($"X-Guard-Kind: {kind}\r\n", StringComparison.Ordinal))
            {
                count++;
            }
        }

        return count;
    }

    /// <summary>The host's phone app, public, with the password grant and the second step's, as a host registers it.</summary>
    private async Task RegisterPhoneAsync()
    {
        using IServiceScope scope = _factory!.Services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "mobile",
            ClientType = ClientTypes.Public,
            Permissions =
            {
                Permissions.Endpoints.Token, Permissions.GrantTypes.Password, Permissions.GrantTypes.RefreshToken,
                Permissions.Prefixes.GrantType + new GuardNames().SecondFactorGrantType,
                Permissions.Prefixes.Scope + "api", Permissions.Prefixes.Scope + Scopes.OfflineAccess,
            },
        });
    }

    private static FormUrlEncodedContent Form(params (string Key, string Value)[] values) => new(values.Select(v => new KeyValuePair<string, string>(v.Key, v.Value)));
}
