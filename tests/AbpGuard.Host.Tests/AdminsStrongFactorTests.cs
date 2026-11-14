using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Npgsql;

namespace AbpGuard.Host.Tests;

/// <summary>
/// The site admins' rule through the sample host (Guard__Admins__RequireStrongFactor): a site admin without a strong
/// factor has a grace from when Guard first sees them, works as usual in it and is told by when; past it, signing in sets
/// one up first; they can't remove their last; another admin removes a lost passkey, and a reset restarts the grace.
/// Each step is in the security log, and Administration's security settings show the rule, read-only.
/// Needs Postgres: localhost:5432 (postgres/postgres), or the server GUARD_TEST_POSTGRES names.
/// </summary>
[Collection(SampleHost.Collection)]
public sealed class AdminsStrongFactorTests : IAsyncLifetime
{
    private static readonly string Server =
        Environment.GetEnvironmentVariable("GUARD_TEST_POSTGRES") is { Length: > 0 } server ? server : "Host=localhost;Port=5432;Username=postgres;Password=postgres";
    private const string AdminPassword = "Host-Admin-Pass-1";
    private const string Password = "Admins-Pass-12345";
    private static readonly string CsrfHeader = new GuardNames().CsrfHeader;
    private static readonly Guid Admins = Guid.Parse("00000000-0000-0000-0000-00000000a001");
    private static readonly (string Key, string Value)[] Rule = [("Guard__Admins__RequireStrongFactor", "true"), ("Guard__Admins__GraceHours", "48")];

    private readonly string _database = "guard_admins_" + Guid.NewGuid().ToString("N")[..12];
    private readonly string _mail = Path.Combine(Path.GetTempPath(), "guard-admins-mail-" + Guid.NewGuid().ToString("N"));
    private WebApplicationFactory<Program>? _factory;

    public Task InitializeAsync()
    {
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");
        Environment.SetEnvironmentVariable("ConnectionStrings__Guard", $"{Server};Database={_database}");
        Environment.SetEnvironmentVariable("Guard__Seed__AdminPassword", AdminPassword);
        Environment.SetEnvironmentVariable("Guard__Messenger__PickupFolder", _mail);
        // The default strong categories but `accounts`, so the set-up's admin, with no factor yet, makes its people.
        Environment.SetEnvironmentVariable("Guard__StepUp__Strong", "plugins,roles,security,directories,apps,service-accounts,admin-tokens,exports,backups,scripts,secrets,sites");
        foreach ((string key, string value) in Rule)
        {
            Environment.SetEnvironmentVariable(key, value);
        }

        _factory = new WebApplicationFactory<Program>();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        if (_factory is not null)
        {
            await _factory.DisposeAsync();
        }

        foreach ((string key, _) in Rule)
        {
            Environment.SetEnvironmentVariable(key, null);
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
    }

    [Fact]
    public async Task A_site_admin_has_a_grace_and_past_it_signs_in_by_setting_up_a_strong_factor()
    {
        // Signing in starts the grace: the admin works as usual and is told by when.
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);
        using (JsonDocument me = JsonDocument.Parse(await admin.GetStringAsync("/api/guard/me")))
        {
            JsonElement strong = me.RootElement.GetProperty("strongFactor");
            Assert.False(strong.GetProperty("has").GetBoolean());
            Assert.Empty(strong.GetProperty("methods").EnumerateArray());
            Assert.False(strong.GetProperty("overdue").GetBoolean());
            Assert.InRange(strong.GetProperty("requiredBy").GetDateTime(), DateTime.UtcNow.AddHours(47.9), DateTime.UtcNow.AddHours(48.1));
        }

        Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/accounts",
            new { username = "wes", displayName = "Wes", email = "wes@example.test", password = Password })).StatusCode);

        // The rule is the environment's, shown read-only.
        using (JsonDocument settings = JsonDocument.Parse(await admin.GetStringAsync("/api/guard/security/settings")))
        {
            JsonElement rule = settings.RootElement.GetProperty("adminsStrongFactor");
            Assert.True(rule.GetProperty("required").GetBoolean());
            Assert.Equal(48, rule.GetProperty("graceHours").GetInt32());
            Assert.Equal("environment", rule.GetProperty("source").GetString());
            Assert.Equal("Guard__Admins__RequireStrongFactor", rule.GetProperty("variable").GetString());
        }

        // Past the grace, signing in sets up a strong factor first: a passkey here.
        await ExecuteAsync("UPDATE guard.accounts SET \"StrongFactorDueAt\" = now() - interval '1 hour' WHERE \"Username\" = 'admin'");
        HttpClient visitor = Client();
        HttpResponseMessage asked = await visitor.PostAsJsonAsync("/api/guard/session", new { username = "admin", password = AdminPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, asked.StatusCode);
        string ticket;
        using (JsonDocument step = JsonDocument.Parse(await asked.Content.ReadAsStringAsync()))
        {
            JsonElement second = step.RootElement.GetProperty("secondFactor");
            Assert.True(second.GetProperty("enrol").GetBoolean());
            Assert.True(second.GetProperty("strong").GetBoolean());
            ticket = second.GetProperty("ticket").GetString()!;
        }

        using SoftwareAuthenticator key = new();
        JsonElement created = JsonDocument.Parse(await (await visitor.PostAsJsonAsync("/api/guard/second-factor/enrol/passkey/options", new { ticket })).Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(HttpStatusCode.OK, (await visitor.PostAsJsonAsync("/api/guard/second-factor/enrol/passkey", new { ticket, name = "Admin's key", credential = key.Register(created) })).StatusCode);
        HttpResponseMessage signedIn = await visitor.PostAsJsonAsync("/api/guard/session/second-factor", new { ticket, method = (string?)null, code = (string?)null });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        string visitorCsrf = CsrfOf(signedIn);
        using (JsonDocument me = JsonDocument.Parse(await visitor.GetStringAsync("/api/guard/me")))
        {
            JsonElement strong = me.RootElement.GetProperty("strongFactor");
            Assert.True(strong.GetProperty("has").GetBoolean());
            Assert.Equal(["passkey"], strong.GetProperty("methods").EnumerateArray().Select(m => m.GetString()!).ToArray());
            Assert.Equal(JsonValueKind.Null, strong.GetProperty("requiredBy").ValueKind);
        }

        // Their last strong factor stays while the rule holds, even after a strong step-up.
        JsonElement stepOptions = await OptionsAsync(visitor, visitorCsrf, "/api/guard/session/step-up/options");
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(visitor, visitorCsrf, HttpMethod.Post, "/api/guard/session/step-up", new { method = "passkey", credential = key.Assert(stepOptions) })).StatusCode);
        Guid passkey = await FactorIdAsync(visitor);
        await AssertErrorAsync(await SendAsync(visitor, visitorCsrf, HttpMethod.Delete, $"/api/guard/me/second-factors/{passkey}", new { }), HttpStatusCode.BadRequest, "last_strong_factor");

        Assert.Equal("account.strong-factor.grace,auth.strong-factor.enrol,account.second-factor.added,account.strong-factor.set-up", await ScalarAsync(
            "SELECT string_agg(\"Type\", ',' ORDER BY \"Time\") FROM guard.security_events WHERE \"Type\" LIKE '%strong-factor%' OR \"Type\" = 'account.second-factor.added'"));
    }

    [Fact]
    public async Task Another_admin_removes_a_lost_passkey_and_a_reset_restarts_the_grace()
    {
        // The admin sets up a passkey (their first: the password's sign-in will do) and steps up with it.
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);
        using SoftwareAuthenticator adminKey = new();
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/me/passkeys",
            new { name = "Admin's key", credential = adminKey.Register(await OptionsAsync(admin, csrf, "/api/guard/me/passkeys/options")) })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/session/step-up",
            new { method = "passkey", credential = adminKey.Assert(await OptionsAsync(admin, csrf, "/api/guard/session/step-up/options")) })).StatusCode);

        // Vic becomes a site admin and sets up two passkeys.
        Guid vic = await IdAsync(await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/accounts",
            new { username = "vic", displayName = "Vic", email = "vic@example.test", password = Password }));
        Assert.True((await SendAsync(admin, csrf, HttpMethod.Post, $"/api/guard/groups/{Admins}/members", new { accountId = vic, groupId = (Guid?)null })).IsSuccessStatusCode);
        HttpClient browser = Client();
        string vicCsrf = await SignInAsync(browser, "vic", Password);
        using SoftwareAuthenticator phone = new();
        using SoftwareAuthenticator laptop = new();
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(browser, vicCsrf, HttpMethod.Post, "/api/guard/me/passkeys",
            new { name = "Vic's phone", credential = phone.Register(await OptionsAsync(browser, vicCsrf, "/api/guard/me/passkeys/options")) })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(browser, vicCsrf, HttpMethod.Post, "/api/guard/session/step-up",
            new { method = "passkey", credential = phone.Assert(await OptionsAsync(browser, vicCsrf, "/api/guard/session/step-up/options")) })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(browser, vicCsrf, HttpMethod.Post, "/api/guard/me/passkeys",
            new { name = "Vic's laptop", credential = laptop.Register(await OptionsAsync(browser, vicCsrf, "/api/guard/me/passkeys/options")) })).StatusCode);

        // The admin's view: the same as Vic's own.
        Guid lost;
        using (JsonDocument view = JsonDocument.Parse(await admin.GetStringAsync($"/api/guard/accounts/{vic}/second-factors")))
        {
            JsonElement[] factors = [.. view.RootElement.GetProperty("factors").EnumerateArray()];
            Assert.Equal(["Vic's phone", "Vic's laptop"], factors.Select(f => f.GetProperty("name").GetString()!).ToArray());
            Assert.All(factors, f => Assert.True(f.GetProperty("strong").GetBoolean()));
            Assert.True(view.RootElement.GetProperty("strong").GetBoolean());
            lost = factors[0].GetProperty("id").GetGuid();
        }

        // A lost phone's passkey goes, and Vic is told; their last can't go this way, only by a reset.
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, csrf, HttpMethod.Delete, $"/api/guard/accounts/{vic}/second-factors/{lost}", new { })).StatusCode);
        Assert.Contains("An administrator removed the passkey “Vic's phone”", await MailAsync("vic@example.test", "guard.second-factor-removed"), StringComparison.Ordinal);
        Guid last = (Guid)(await ScalarAsync("SELECT \"Id\" FROM guard.passkeys WHERE \"AccountId\" = @id", vic))!;
        await AssertErrorAsync(await SendAsync(admin, csrf, HttpMethod.Delete, $"/api/guard/accounts/{vic}/second-factors/{last}", new { }), HttpStatusCode.BadRequest, "last_strong_factor");

        // The reset takes everything and starts Vic's grace again.
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, csrf, HttpMethod.Delete, $"/api/guard/accounts/{vic}/second-factors", new { })).StatusCode);
        Assert.Equal(0L, await ScalarAsync("SELECT count(*) FROM guard.passkeys WHERE \"AccountId\" = @id", vic));
        Assert.Equal(true, await ScalarAsync("SELECT \"StrongFactorDueAt\" > now() + interval '47 hours' FROM guard.accounts WHERE \"Id\" = @id", vic));
        Assert.Equal(1L, await ScalarAsync("SELECT count(*) FROM guard.security_events WHERE \"Type\" = 'account.strong-factor.grace' AND \"TargetId\" = @id", vic));
    }

    // ---- helpers ----

    private HttpClient Client() => _factory!.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });

    private static async Task<string> SignInAsync(HttpClient client, string username, string password)
    {
        HttpResponseMessage signedIn = await client.PostAsJsonAsync("/api/guard/session", new { username, password });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        return CsrfOf(signedIn);
    }

    private static string CsrfOf(HttpResponseMessage response)
    {
        string prefix = new GuardCookieOptions().Csrf + "=";
        string cookie = response.Headers.GetValues("Set-Cookie").First(c => c.StartsWith(prefix, StringComparison.Ordinal));
        return Uri.UnescapeDataString(cookie[prefix.Length..].Split(';')[0]);
    }

    private static async Task<Guid> FactorIdAsync(HttpClient client)
    {
        using JsonDocument mine = JsonDocument.Parse(await client.GetStringAsync("/api/guard/me/second-factors"));
        return Assert.Single(mine.RootElement.GetProperty("factors").EnumerateArray()).GetProperty("id").GetGuid();
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

    private static async Task<Guid> IdAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("id").GetGuid();
    }

    private static async Task AssertErrorAsync(HttpResponseMessage response, HttpStatusCode status, string code)
    {
        string text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == status, $"{(int)response.StatusCode}: {text}");
        using JsonDocument body = JsonDocument.Parse(text);
        Assert.Equal(code, body.RootElement.GetProperty("error").GetProperty("code").GetString());
    }

    /// <summary>The newest mail of a kind to an address in the pickup folder.</summary>
    private async Task<string> MailAsync(string address, string kind)
    {
        foreach (string file in Directory.GetFiles(_mail, "*.eml").OrderDescending(StringComparer.Ordinal))
        {
            string mail = await File.ReadAllTextAsync(file);
            if (mail.Contains($"<{address}>", StringComparison.Ordinal) && mail.Contains($"X-Guard-Kind: {kind}\r\n", StringComparison.Ordinal))
            {
                return mail;
            }
        }

        throw new InvalidOperationException($"No {kind} mail to {address}.");
    }

    private async Task<object?> ScalarAsync(string sql, Guid? id = null)
    {
        await using NpgsqlConnection connection = new($"{Server};Database={_database}");
        await connection.OpenAsync();
        await using NpgsqlCommand command = new(sql, connection);
        if (id is { } value)
        {
            command.Parameters.AddWithValue("id", value);
        }

        return await command.ExecuteScalarAsync();
    }

    private async Task ExecuteAsync(string sql)
    {
        await using NpgsqlConnection connection = new($"{Server};Database={_database}");
        await connection.OpenAsync();
        await using NpgsqlCommand command = new(sql, connection);
        await command.ExecuteNonQueryAsync();
    }
}
