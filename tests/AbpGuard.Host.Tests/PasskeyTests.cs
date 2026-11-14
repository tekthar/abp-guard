using System.IO.Compression;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.Testing;
using Npgsql;

namespace AbpGuard.Host.Tests;

/// <summary>
/// Passkeys through the sample host, with a software authenticator: added with the device's answer, a step-up with one
/// alone (strong), a sign-in's second step and enrolment with one, and every answer refused that must be: another
/// origin, a challenge used or expired, a signature count that went back. A merge drops the merged account's passkeys;
/// an erasure removes them; an export names them.
/// Needs Postgres: localhost:5432 (postgres/postgres), or the server GUARD_TEST_POSTGRES names.
/// </summary>
[Collection(SampleHost.Collection)]
public sealed class PasskeyTests : IAsyncLifetime
{
    private static readonly string Server =
        Environment.GetEnvironmentVariable("GUARD_TEST_POSTGRES") is { Length: > 0 } server ? server : "Host=localhost;Port=5432;Username=postgres;Password=postgres";
    private const string AdminPassword = "Host-Admin-Pass-1";
    private const string Password = "Passkey-Pass-12345";
    private static readonly string CsrfHeader = new GuardNames().CsrfHeader;
    private static readonly string[] Features = ["Merges"];

    private readonly string _database = "guard_passkeys_" + Guid.NewGuid().ToString("N")[..12];
    private readonly string _mail = Path.Combine(Path.GetTempPath(), "guard-passkeys-mail-" + Guid.NewGuid().ToString("N"));
    private WebApplicationFactory<Program>? _factory;

    public Task InitializeAsync()
    {
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");
        Environment.SetEnvironmentVariable("ConnectionStrings__Guard", $"{Server};Database={_database}");
        Environment.SetEnvironmentVariable("Guard__Seed__AdminPassword", AdminPassword);
        Environment.SetEnvironmentVariable("Guard__Messenger__PickupFolder", _mail);
        foreach (string feature in Features)
        {
            Environment.SetEnvironmentVariable($"Guard__Features__{feature}", "true");
        }

        // Guard's default levels: roles, security and the rest strong.
        Environment.SetEnvironmentVariable("Guard__StepUp__Strong", null);
        _factory = new WebApplicationFactory<Program>();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        if (_factory is not null)
        {
            await _factory.DisposeAsync();
        }

        foreach (string feature in Features)
        {
            Environment.SetEnvironmentVariable($"Guard__Features__{feature}", null);
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
    public async Task A_person_adds_a_passkey_steps_up_with_it_alone_and_signs_in_with_it_as_the_second_step()
    {
        Guid pia = await PersonAsync("pia");
        HttpClient browser = Client();
        string csrf = await SignInAsync(browser, "pia", Password);
        using SoftwareAuthenticator phone = new();

        // The options: discoverable, with user verification, for the site's address and the person's handle.
        JsonElement created = await OptionsAsync(browser, csrf, "/api/guard/me/passkeys/options");
        Assert.Equal("localhost", created.GetProperty("rp").GetProperty("id").GetString());
        Assert.Equal("required", created.GetProperty("authenticatorSelection").GetProperty("residentKey").GetString());
        Assert.Equal("required", created.GetProperty("authenticatorSelection").GetProperty("userVerification").GetString());
        Assert.Equal(SoftwareAuthenticator.B64(pia.ToByteArray()), created.GetProperty("user").GetProperty("id").GetString());

        // Added: a strong factor with its name and provider, synced, and the first factor's recovery codes.
        HttpResponseMessage added = await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/me/passkeys", new { name = "Pia's phone", credential = phone.Register(created) });
        Assert.Equal(HttpStatusCode.OK, added.StatusCode);
        using JsonDocument passkey = JsonDocument.Parse(await added.Content.ReadAsStringAsync());
        Guid id = passkey.RootElement.GetProperty("id").GetGuid();
        Assert.Equal("passkey", passkey.RootElement.GetProperty("kind").GetString());
        Assert.True(passkey.RootElement.GetProperty("strong").GetBoolean());
        Assert.True(passkey.RootElement.GetProperty("backedUp").GetBoolean());
        Assert.Equal("iCloud Keychain", passkey.RootElement.GetProperty("provider").GetString());
        Assert.Equal(10, passkey.RootElement.GetProperty("recoveryCodes").GetArrayLength());

        using (JsonDocument mine = JsonDocument.Parse(await browser.GetStringAsync("/api/guard/me/second-factors")))
        {
            JsonElement factor = Assert.Single(mine.RootElement.GetProperty("factors").EnumerateArray());
            Assert.Equal("Pia's phone", factor.GetProperty("name").GetString());
            Assert.True(factor.GetProperty("strong").GetBoolean());
            Assert.True(mine.RootElement.GetProperty("strong").GetBoolean());
        }

        // A second factor needs a strong step-up now: the password alone signed this session in.
        await AssertErrorAsync(await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/me/passkeys/options", new { }), HttpStatusCode.Forbidden, "step_up_required");

        // A step-up with the passkey alone: both times now.
        JsonElement asked = await OptionsAsync(browser, csrf, "/api/guard/session/step-up/options");
        Assert.Equal(phone.Id, Assert.Single(asked.GetProperty("allowCredentials").EnumerateArray()).GetProperty("id").GetString());
        Assert.Equal("required", asked.GetProperty("userVerification").GetString());
        HttpResponseMessage stepped = await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/session/step-up", new { method = "passkey", credential = phone.Assert(asked) });
        Assert.Equal(HttpStatusCode.OK, stepped.StatusCode);
        using (JsonDocument proof = JsonDocument.Parse(await stepped.Content.ReadAsStringAsync()))
        {
            Assert.Equal(proof.RootElement.GetProperty("authTime").GetDateTime(), proof.RootElement.GetProperty("strongAuthTime").GetDateTime());
        }

        // The same device again, now strongly stepped up: its passkey is excluded, and refused if it answers anyway.
        JsonElement again = await OptionsAsync(browser, csrf, "/api/guard/me/passkeys/options");
        Assert.Equal(phone.Id, Assert.Single(again.GetProperty("excludeCredentials").EnumerateArray()).GetProperty("id").GetString());
        await AssertErrorAsync(await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/me/passkeys", new { name = "Again", credential = phone.Register(again) }),
            HttpStatusCode.BadRequest, "passkey_exists");

        // A challenge is good once.
        await AssertErrorAsync(await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/session/step-up", new { method = "passkey", credential = phone.Assert(asked) }),
            HttpStatusCode.BadRequest, "passkey_rejected");

        // Another origin is refused, and so is a challenge past its five minutes.
        JsonElement elsewhere = await OptionsAsync(browser, csrf, "/api/guard/session/step-up/options");
        await AssertErrorAsync(await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/session/step-up",
            new { method = "passkey", credential = phone.Assert(elsewhere, origin: "https://evil.example") }), HttpStatusCode.BadRequest, "passkey_rejected");
        JsonElement late = await OptionsAsync(browser, csrf, "/api/guard/session/step-up/options");
        await ExecuteAsync("UPDATE guard.passkey_challenges SET \"ExpiresAt\" = now() - interval '1 minute'");
        await AssertErrorAsync(await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/session/step-up", new { method = "passkey", credential = phone.Assert(late) }),
            HttpStatusCode.BadRequest, "passkey_rejected");

        // A signature count that went back is a copied passkey: refused, and the next real one still passes.
        uint reached = phone.Counter;
        JsonElement copied = await OptionsAsync(browser, csrf, "/api/guard/session/step-up/options");
        await AssertErrorAsync(await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/session/step-up",
            new { method = "passkey", credential = phone.Assert(copied, counter: 1) }), HttpStatusCode.BadRequest, "passkey_rejected");
        phone.Counter = reached + 5;
        JsonElement honest = await OptionsAsync(browser, csrf, "/api/guard/session/step-up/options");
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/session/step-up", new { method = "passkey", credential = phone.Assert(honest) })).StatusCode);

        // Signing in again: the passkey is the second step, and the session it starts is strong.
        HttpClient other = Client();
        HttpResponseMessage signIn = await other.PostAsJsonAsync("/api/guard/session", new { username = "pia", password = Password });
        Assert.Equal(HttpStatusCode.Unauthorized, signIn.StatusCode);
        string ticket;
        using (JsonDocument step = JsonDocument.Parse(await signIn.Content.ReadAsStringAsync()))
        {
            ticket = step.RootElement.GetProperty("secondFactor").GetProperty("ticket").GetString()!;
            Assert.Equal(["passkey"], step.RootElement.GetProperty("secondFactor").GetProperty("methods").EnumerateArray().Select(m => m.GetString()!).ToArray());
        }

        HttpResponseMessage stepOptions = await other.PostAsJsonAsync("/api/guard/session/second-step/options", new { ticket });
        Assert.Equal(HttpStatusCode.OK, stepOptions.StatusCode);
        JsonElement second = JsonDocument.Parse(await stepOptions.Content.ReadAsStringAsync()).RootElement;
        await AssertErrorAsync(await other.PostAsJsonAsync("/api/guard/session/second-factor",
            new { ticket, method = "passkey", credential = phone.Assert(second, origin: "https://evil.example") }), HttpStatusCode.BadRequest, "second_factor_failed");
        second = JsonDocument.Parse(await (await other.PostAsJsonAsync("/api/guard/session/second-step/options", new { ticket })).Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(HttpStatusCode.OK, (await other.PostAsJsonAsync("/api/guard/session/second-factor", new { ticket, method = "passkey", credential = phone.Assert(second) })).StatusCode);
        Assert.Equal(true, await ScalarAsync(
            "SELECT \"StrongAuthTime\" = \"AuthTime\" FROM guard.sessions WHERE \"AccountId\" = @id ORDER BY \"CreatedAt\" DESC LIMIT 1", pia));

        // Renamed, then removed: the last factor takes the recovery codes with it.
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(browser, csrf, HttpMethod.Put, $"/api/guard/me/passkeys/{id}", new { name = "Pia's laptop" })).StatusCode);
        Assert.Equal("Pia's laptop", await ScalarAsync("SELECT \"Name\" FROM guard.passkeys WHERE \"AccountId\" = @id", pia));
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(browser, csrf, HttpMethod.Delete, $"/api/guard/me/second-factors/{id}", new { })).StatusCode);
        Assert.Equal(0L, await ScalarAsync("SELECT count(*) FROM guard.passkeys WHERE \"AccountId\" = @id", pia));
        Assert.Equal(0L, await ScalarAsync("SELECT count(*) FROM guard.recovery_codes WHERE \"AccountId\" = @id", pia));
        Assert.Equal("account.second-factor.added,account.second-factor.removed", await ScalarAsync(
            "SELECT string_agg(\"Type\", ',' ORDER BY \"Time\") FROM guard.security_events WHERE \"TargetId\" = @id AND \"Type\" LIKE 'account.second-factor.%'", pia));
    }

    [Fact]
    public async Task A_strong_group_sets_up_a_passkey_at_sign_in_and_takes_it_as_the_second_step()
    {
        (HttpClient admin, string adminCsrf, SoftwareAuthenticator adminKey) = await StrongAdminAsync();
        using SoftwareAuthenticator _ = adminKey;
        Guid quinn = await PersonAsync("quinn", admin, adminCsrf);
        Guid group = await IdAsync(await SendAsync(admin, adminCsrf, HttpMethod.Post, "/api/guard/groups", new { name = "needs-strong", description = (string?)null, directoryId = (Guid?)null }));
        Assert.True((await SendAsync(admin, adminCsrf, HttpMethod.Post, $"/api/guard/groups/{group}/members", new { accountId = quinn, groupId = (Guid?)null })).IsSuccessStatusCode);
        Assert.True((await SendAsync(admin, adminCsrf, HttpMethod.Put, $"/api/guard/groups/{group}/two-factor", new { mode = "strong" })).IsSuccessStatusCode);

        // No factor yet: the step is to set one up, and the ticket sets up a passkey.
        HttpClient visitor = Client();
        (string ticket, bool enrol, bool strong, string[] methods) = await ChallengeAsync(visitor, "quinn");
        Assert.True(enrol);
        Assert.True(strong);
        Assert.Empty(methods);
        using SoftwareAuthenticator key = new() { AaGuid = Guid.Parse("cb69481e-8ff7-4039-93ec-0a2729a154a8"), Synced = false };
        HttpResponseMessage options = await visitor.PostAsJsonAsync("/api/guard/second-factor/enrol/passkey/options", new { ticket });
        Assert.Equal(HttpStatusCode.OK, options.StatusCode);
        JsonElement created = JsonDocument.Parse(await options.Content.ReadAsStringAsync()).RootElement;
        HttpResponseMessage enrolled = await visitor.PostAsJsonAsync("/api/guard/second-factor/enrol/passkey", new { ticket, name = "Desk key", credential = key.Register(created) });
        Assert.Equal(HttpStatusCode.OK, enrolled.StatusCode);
        using (JsonDocument body = JsonDocument.Parse(await enrolled.Content.ReadAsStringAsync()))
        {
            Assert.Equal("YubiKey 5 Series", body.RootElement.GetProperty("provider").GetString());
            Assert.False(body.RootElement.GetProperty("backedUp").GetBoolean());
            Assert.Equal(10, body.RootElement.GetProperty("recoveryCodes").GetArrayLength());
        }

        Assert.Equal(HttpStatusCode.OK, (await visitor.PostAsJsonAsync("/api/guard/session/second-factor", new { ticket, method = (string?)null, code = (string?)null })).StatusCode);

        // Next time the strong group takes the passkey as the step.
        HttpClient next = Client();
        (ticket, enrol, strong, methods) = await ChallengeAsync(next, "quinn");
        Assert.False(enrol);
        Assert.True(strong);
        Assert.Equal(["passkey"], methods);
        JsonElement asked = JsonDocument.Parse(await (await next.PostAsJsonAsync("/api/guard/session/second-step/options", new { ticket })).Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(HttpStatusCode.OK, (await next.PostAsJsonAsync("/api/guard/session/second-factor", new { ticket, method = "passkey", credential = key.Assert(asked) })).StatusCode);

        // A ticket used up gives no options.
        await AssertErrorAsync(await next.PostAsJsonAsync("/api/guard/session/second-step/options", new { ticket }), HttpStatusCode.Unauthorized, "ticket_expired");
    }

    [Fact]
    public async Task A_merge_drops_the_merged_accounts_passkeys_an_export_names_them_and_an_erasure_removes_them()
    {
        (HttpClient admin, string adminCsrf, SoftwareAuthenticator adminKey) = await StrongAdminAsync();
        using SoftwareAuthenticator _ = adminKey;
        Guid old = await PersonAsync("rex-old", admin, adminCsrf);
        Guid kept = await PersonAsync("rex", admin, adminCsrf);
        foreach (string username in new[] { "rex-old", "rex" })
        {
            HttpClient browser = Client();
            string csrf = await SignInAsync(browser, username, Password);
            using SoftwareAuthenticator device = new();
            JsonElement created = await OptionsAsync(browser, csrf, "/api/guard/me/passkeys/options");
            Assert.Equal(HttpStatusCode.OK, (await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/me/passkeys", new { name = $"{username}'s phone", credential = device.Register(created) })).StatusCode);
            if (username == "rex")
            {
                // An export lists the passkey by its name and provider, never its key.
                HttpResponseMessage export = await SendAsync(browser, csrf, HttpMethod.Post, "/api/guard/me/data-export", new { files = false });
                Assert.Equal(HttpStatusCode.OK, export.StatusCode);
                using ZipArchive zip = new(await export.Content.ReadAsStreamAsync());
                ZipArchiveEntry entry = Assert.Single(zip.Entries, e => e.FullName.Contains("passkeys", StringComparison.Ordinal));
                using StreamReader reader = new(entry.Open());
                string text = await reader.ReadToEndAsync();
                Assert.Contains("rex's phone", text, StringComparison.Ordinal);
                Assert.Contains("iCloud Keychain", text, StringComparison.Ordinal);
                Assert.DoesNotContain("publicKey", text, StringComparison.OrdinalIgnoreCase);
            }
        }

        // The merged account's passkey goes: its credential carries that account's handle, not the survivor's.
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, adminCsrf, HttpMethod.Post, $"/api/guard/accounts/{old}/merge", new { survivorId = kept, confirm = "rex-old" })).StatusCode);
        Assert.Equal(0L, await ScalarAsync("SELECT count(*) FROM guard.passkeys WHERE \"AccountId\" = @id", old));
        Assert.Equal(1L, await ScalarAsync("SELECT count(*) FROM guard.passkeys WHERE \"AccountId\" = @id", kept));

        // An erased account keeps none.
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, adminCsrf, HttpMethod.Post, $"/api/guard/accounts/{kept}/erasure", new { })).StatusCode);
        Assert.Equal(0L, await ScalarAsync("SELECT count(*) FROM guard.passkeys WHERE \"AccountId\" = @id", kept));
    }

    // ---- helpers ----

    private HttpClient Client() => _factory!.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });

    private async Task<(HttpClient Admin, string Csrf)> AdminAsync()
    {
        HttpClient admin = Client();
        return (admin, await SignInAsync(admin, "admin", AdminPassword));
    }

    /// <summary>The admin signed in, with a passkey of their own, and stepped up with it: strong for the site's window.</summary>
    private async Task<(HttpClient Admin, string Csrf, SoftwareAuthenticator Key)> StrongAdminAsync()
    {
        (HttpClient admin, string csrf) = await AdminAsync();
        SoftwareAuthenticator key = new();
        JsonElement created = await OptionsAsync(admin, csrf, "/api/guard/me/passkeys/options");
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/me/passkeys", new { name = "Admin's key", credential = key.Register(created) })).StatusCode);
        JsonElement asked = await OptionsAsync(admin, csrf, "/api/guard/session/step-up/options");
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/session/step-up", new { method = "passkey", credential = key.Assert(asked) })).StatusCode);
        return (admin, csrf, key);
    }

    /// <summary>A person in the internal directory ({username}@example.test, <see cref="Password"/>).</summary>
    private async Task<Guid> PersonAsync(string username, HttpClient? admin = null, string? csrf = null)
    {
        if (admin is null)
        {
            (admin, csrf) = await AdminAsync();
        }

        return await IdAsync(await SendAsync(admin, csrf!, HttpMethod.Post, "/api/guard/accounts",
            new { username, displayName = username, email = $"{username}@example.test", password = Password }));
    }

    private static async Task<string> SignInAsync(HttpClient client, string username, string password)
    {
        HttpResponseMessage signedIn = await client.PostAsJsonAsync("/api/guard/session", new { username, password });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        string prefix = new GuardCookieOptions().Csrf + "=";
        string cookie = signedIn.Headers.GetValues("Set-Cookie").First(c => c.StartsWith(prefix, StringComparison.Ordinal));
        return Uri.UnescapeDataString(cookie[prefix.Length..].Split(';')[0]);
    }

    /// <summary>Signs in with the password where a second step is asked: the ticket, whether to set one up, whether strong, and the methods.</summary>
    private static async Task<(string Ticket, bool Enrol, bool Strong, string[] Methods)> ChallengeAsync(HttpClient client, string username)
    {
        HttpResponseMessage asked = await client.PostAsJsonAsync("/api/guard/session", new { username, password = Password });
        Assert.Equal(HttpStatusCode.Unauthorized, asked.StatusCode);
        using JsonDocument body = JsonDocument.Parse(await asked.Content.ReadAsStringAsync());
        JsonElement step = body.RootElement.GetProperty("secondFactor");
        return (step.GetProperty("ticket").GetString()!, step.GetProperty("enrol").GetBoolean(), step.GetProperty("strong").GetBoolean(),
            step.GetProperty("methods").EnumerateArray().Select(m => m.GetString()!).ToArray());
    }

    private static async Task<JsonElement> OptionsAsync(HttpClient client, string csrf, string path)
    {
        HttpResponseMessage response = await SendAsync(client, csrf, HttpMethod.Post, path, new { });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
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
