using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OpenIddict.Abstractions;
using AbpGuard.Services.TwoFactor;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AbpGuard.Host.Tests;

/// <summary>The sample host's tests set the process's environment, so they run one at a time.</summary>
[CollectionDefinition(Collection, DisableParallelization = true)]
public sealed class SampleHost
{
    public const string Collection = "Sample host";
}

/// <summary>
/// What a right short of an admin's, a sign-in ticket, a token or an anonymous visitor mustn't reach: setting up an app
/// in place of an emailed code, adding a verified address, merging rights into oneself, locking an admin, allowing an app
/// without the browser, a header of their own in a mail, another's pending sign-up, more tries than the limits, and a
/// session past a password reset. Each also shows what stays allowed.
/// Needs Postgres: localhost:5432 (postgres/postgres), or the server GUARD_TEST_POSTGRES names.
/// </summary>
[Collection(SampleHost.Collection)]
public sealed partial class SecurityTests : IAsyncLifetime
{
    private static readonly string Server =
        Environment.GetEnvironmentVariable("GUARD_TEST_POSTGRES") is { Length: > 0 } server ? server : "Host=localhost;Port=5432;Username=postgres;Password=postgres";
    private const string AdminPassword = "Host-Admin-Pass-1";
    private const string Password = "Password-12345";
    private static readonly string CsrfHeader = new GuardNames().CsrfHeader;
    private static readonly Guid Internal = Guid.Parse("00000000-0000-0000-0000-00000000d001");
    private static readonly Guid Admins = Guid.Parse("00000000-0000-0000-0000-00000000a001");
    private static readonly Guid Helpdesk = Guid.Parse("00000000-0000-0000-0000-0000000000b2");
    private static readonly string[] Features = ["Merges", "OAuthApps", "ClientRegistration", "Handoff"];

    private readonly string _database = "guard_security_" + Guid.NewGuid().ToString("N")[..12];
    private readonly string _mail = Path.Combine(Path.GetTempPath(), "guard-security-mail-" + Guid.NewGuid().ToString("N"));
    private WebApplicationFactory<Program>? _factory;

    /// <summary>The header a test gives a request's client address in: the test server has none of its own.</summary>
    private const string TestIpHeader = "X-Test-Ip";

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

        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(host => host.ConfigureServices(s => s.AddSingleton<IStartupFilter>(new TestAddresses())));
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

        Environment.SetEnvironmentVariable("Guard__Features__PersonalTokens", null);

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
    public async Task A_ticket_sets_up_an_app_only_when_the_person_has_no_way_through_the_step()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        await AddToAdminsAsync(admin, await CreateAccountAsync(admin, "carol", "carol@example.test"));
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(HttpMethod.Put, $"/api/guard/groups/{Admins}/two-factor", new { mode = "required" })).Code);

        // No app and no codes the site sends: the ticket sets the app up.
        JsonElement enrol = await ChallengeAsync("carol");
        Assert.True(enrol.GetProperty("enrol").GetBoolean());
        Assert.Equal(HttpStatusCode.OK, (await Client().PostAsJsonAsync("/api/guard/second-factor/enrol/app", new { ticket = enrol.GetProperty("ticket").GetString() })).StatusCode);

        // The site mails codes: the step asks for one, and the ticket can't set up an app in its place.
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(HttpMethod.Put, "/api/guard/security/second-factor", new { methods = new[] { "email" } })).Code);
        JsonElement asked = await ChallengeAsync("carol");
        Assert.False(asked.GetProperty("enrol").GetBoolean());
        string ticket = asked.GetProperty("ticket").GetString()!;
        HttpClient attacker = Client();
        Assert.Equal(HttpStatusCode.Unauthorized, (await attacker.PostAsJsonAsync("/api/guard/second-factor/enrol/app", new { ticket })).StatusCode);
        string code = Totp.Code(Totp.FromBase32(Totp.ToBase32(new byte[20])), Totp.StepAt(DateTimeOffset.UtcNow));
        Assert.Equal(HttpStatusCode.Unauthorized, (await attacker.PostAsJsonAsync("/api/guard/second-factor/enrol/app/confirm", new { ticket, code })).StatusCode);
        Assert.NotEqual(HttpStatusCode.OK, (await attacker.PostAsJsonAsync("/api/guard/session/second-factor", new { ticket })).StatusCode);
    }

    [Fact]
    public async Task Only_an_admin_adds_removes_or_redirects_an_accounts_addresses()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        Guid adminId = await MyIdAsync(admin);
        Guid role = await CreateRoleAsync(admin, "rename-people",
            """{ "action": "update", "subject": "Account", "fields": ["displayName"], "conditions": { "directoryId": { "$in": "${grant.directoryIds}" } } }""",
            """{ "action": "update", "subject": "Account", "fields": ["displayName"], "conditions": { "id": "${user.id}" } }""");
        Guid helper = await CreateAccountAsync(admin, "helper", "helper@corp.example");
        await GrantAsync(admin, role, helper, new { directoryIds = new[] { Internal } });

        Session h = await SignInAsync("helper", Password);
        Assert.Equal(HttpStatusCode.Forbidden, (await h.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{adminId}/emails", new { email = "evil@attacker.example" })).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await h.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{helper}/emails", new { email = "ceo@bigcustomer.example" })).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await h.SendAsync(HttpMethod.Put, $"/api/guard/accounts/{adminId}/mail-to", new { email = "helper@corp.example" })).Code);

        (HttpStatusCode added, string body) = await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{helper}/emails", new { email = "helper@other.example" });
        Assert.Equal(HttpStatusCode.OK, added);
        Assert.Contains("\"verifiedAt\":\"", body);
    }

    [Fact]
    public async Task A_merge_right_short_of_an_admins_moves_no_rights()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        Guid adminId = await MyIdAsync(admin);
        Guid role = await CreateRoleAsync(admin, "dedup",
            """{ "action": "merge", "subject": "Account", "conditions": { "directoryId": { "$in": "${grant.directoryIds}" } } }""");
        Guid deduper = await CreateAccountAsync(admin, "deduper", "deduper@corp.example");
        await GrantAsync(admin, role, deduper, new { directoryIds = new[] { Internal } });
        Guid plain = await CreateAccountAsync(admin, "plain", "plain@corp.example");
        Guid plainToo = await CreateAccountAsync(admin, "plain2", "plain2@corp.example");
        Guid granted = await CreateAccountAsync(admin, "granted", "granted@corp.example");
        await GrantAsync(admin, role, granted, new { directoryIds = new[] { Internal } });

        Session d = await SignInAsync("deduper", Password);
        Assert.Equal(HttpStatusCode.Forbidden, (await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{adminId}/merge", new { survivorId = deduper, confirm = "admin" })).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{plain}/merge", new { survivorId = deduper, confirm = "plain" })).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{adminId}/merge", new { survivorId = plain, confirm = "admin" })).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{granted}/merge", new { survivorId = plain, confirm = "granted" })).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await d.SendAsync(HttpMethod.Get, "/api/guard/roles")).Code);

        // Accounts with no rights of their own still merge, and an admin merges any.
        Assert.Equal(HttpStatusCode.OK, (await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{plain}/merge", new { survivorId = plainToo, confirm = "plain" })).Code);
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{granted}/merge", new { survivorId = adminId, confirm = "granted" })).Code);
    }

    [Fact]
    public async Task A_helpdesk_locks_and_unlocks_people_but_not_an_admin()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        Guid adminId = await MyIdAsync(admin);
        Guid desk = await CreateAccountAsync(admin, "desk", "desk@corp.example");
        Guid person = await CreateAccountAsync(admin, "person", "person@corp.example");
        await GrantAsync(admin, Helpdesk, desk, new { directoryIds = new[] { Internal } });

        Session d = await SignInAsync("desk", Password);
        Assert.Equal(HttpStatusCode.Forbidden, (await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{adminId}/lock")).Code);
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(HttpMethod.Get, "/api/guard/roles")).Code);

        // An admin an admin locked stays locked for the helpdesk; people they lock and unlock as before.
        Guid other = await CreateAccountAsync(admin, "second-admin", "second@corp.example");
        await AddToAdminsAsync(admin, other);
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{other}/lock")).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{other}/unlock")).Code);
        Assert.Equal(HttpStatusCode.OK, (await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{person}/lock")).Code);
        Assert.Equal(HttpStatusCode.OK, (await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{person}/unlock")).Code);
    }

    [Fact]
    public async Task A_password_reset_ends_the_sessions_that_had_the_old_one()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        await CreateAccountAsync(admin, "frank", "frank@example.test");
        Session old = await SignInAsync("frank", Password);
        Assert.Equal(HttpStatusCode.OK, (await old.SendAsync(HttpMethod.Get, "/api/guard/me")).Code);

        HttpClient anyone = Client();
        Assert.Equal(HttpStatusCode.NoContent, (await anyone.PostAsJsonAsync("/api/guard/password/forgot", new { email = "frank@example.test" })).StatusCode);
        string token = TokenIn(await LastMailToAsync("frank@example.test"));
        Assert.Equal(HttpStatusCode.OK, (await anyone.PostAsJsonAsync("/api/guard/password/reset", new { token, password = "Frank-New-Pass-1" })).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await old.SendAsync(HttpMethod.Get, "/api/guard/me")).Code);
        Session renewed = await SignInAsync("frank", "Frank-New-Pass-1");
        Assert.Equal(HttpStatusCode.OK, (await renewed.SendAsync(HttpMethod.Get, "/api/guard/me")).Code);
    }

    [Fact]
    public async Task A_sign_up_link_confirms_its_own_sign_up_and_a_name_is_one_line()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        Assert.Equal(HttpStatusCode.OK,
            (await admin.SendAsync(HttpMethod.Put, "/api/guard/signup/settings", new { enabled = true, directoryId = Internal, emailDomains = Array.Empty<string>() })).Code);

        HttpClient visitor = Client();
        Assert.Equal(HttpStatusCode.BadRequest, (await visitor.PostAsJsonAsync("/api/guard/signup",
            new { email = "eve@example.test", displayName = "Erin\r\nBcc: eve@attacker.example", password = "Erin-Own-Pass-123" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.SendAsync(HttpMethod.Post, "/api/guard/accounts",
            new { username = "mallory", displayName = "Mallory\nX-Injected: yes", email = "mallory@example.test", password = Password })).Code);

        Assert.Equal(HttpStatusCode.NoContent, (await visitor.PostAsJsonAsync("/api/guard/signup",
            new { email = "erin@example.test", displayName = "Erin", password = "Erin-Own-Pass-123" })).StatusCode);
        string first = TokenIn(await LastMailToAsync("erin@example.test"));
        Assert.Equal(HttpStatusCode.NoContent, (await Client().PostAsJsonAsync("/api/guard/signup",
            new { email = "erin@example.test", displayName = "Erin", password = "Attacker-Pass-123" })).StatusCode);
        string second = TokenIn(await LastMailToAsync("erin@example.test"));

        // The first link no longer confirms the address with the password the second sign-up set; the newest does.
        Assert.Equal(HttpStatusCode.BadRequest, (await visitor.PostAsJsonAsync("/api/guard/signup/verify", new { token = first })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Client().PostAsJsonAsync("/api/guard/session", new { username = "erin@example.test", password = "Attacker-Pass-123" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await visitor.PostAsJsonAsync("/api/guard/signup/verify", new { token = second })).StatusCode);
    }

    [Fact]
    public async Task Tries_sent_at_once_count_against_the_limits()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        await CreateAccountAsync(admin, "grace", "grace@example.test");

        // Passwords: five wrong ones in 15 minutes, however many arrive together.
        HttpResponseMessage[] guesses = await Task.WhenAll(Enumerable.Range(0, 12).Select(i =>
            Client().PostAsJsonAsync("/api/guard/session", new { username = "grace", password = $"Wrong-Pass-{i:D4}" })));
        Assert.True(guesses.Count(r => r.StatusCode != HttpStatusCode.TooManyRequests) <= 5, string.Join(",", guesses.Select(r => (int)r.StatusCode)));

        // Second-step codes: five a ticket.
        await CreateAccountAsync(admin, "heidi", "heidi@example.test");
        Session heidi = await SignInAsync("heidi", Password);
        (_, string started) = await heidi.SendAsync(HttpMethod.Post, "/api/guard/me/second-factors/app");
        string code = Totp.Code(Totp.FromBase32(JsonDocument.Parse(started).RootElement.GetProperty("secret").GetString()!), Totp.StepAt(DateTimeOffset.UtcNow));
        Assert.Equal(HttpStatusCode.OK, (await heidi.SendAsync(HttpMethod.Post, "/api/guard/me/second-factors/app/confirm", new { code })).Code);
        string ticket = (await ChallengeAsync("heidi")).GetProperty("ticket").GetString()!;
        HttpResponseMessage[] codes = await Task.WhenAll(Enumerable.Range(0, 12).Select(i =>
            Client().PostAsJsonAsync("/api/guard/session/second-factor", new { ticket, method = "recovery", code = $"WRONG-{i:D5}" })));
        Assert.True(codes.Count(r => r.StatusCode == HttpStatusCode.BadRequest) <= 5, string.Join(",", codes.Select(r => (int)r.StatusCode)));
    }

    [Fact]
    public async Task Only_the_browsers_session_allows_an_app()
    {
        string access = await PhoneAccessTokenAsync();
        await LetAppsRegisterAsync();
        HttpResponseMessage registered = await Client().PostAsJsonAsync("/connect/register", new { client_name = "An app", redirect_uris = new[] { "https://app.example/cb" } });
        Assert.Equal(HttpStatusCode.Created, registered.StatusCode);
        string clientId = JsonDocument.Parse(await registered.Content.ReadAsStringAsync()).RootElement.GetProperty("client_id").GetString()!;

        // The phone's token, from the password grant: it can't allow the app.
        using HttpRequestMessage withToken = Allow(clientId, null);
        withToken.Headers.Authorization = new("Bearer", access);
        HttpResponseMessage refused = await Client().SendAsync(withToken);
        Assert.DoesNotContain("code=", refused.Headers.Location?.Query ?? "");
        Assert.Contains("error=access_denied", refused.Headers.Location?.Query ?? "");

        // The person at the browser can.
        Session admin = await SignInAsync("admin", AdminPassword);
        using HttpRequestMessage fromBrowser = Allow(clientId, admin.Csrf);
        HttpResponseMessage allowed = await admin.Http.SendAsync(fromBrowser);
        Assert.Contains("code=", allowed.Headers.Location?.Query ?? "");
    }

    [Fact]
    public async Task An_access_token_stops_when_its_sign_in_ends()
    {
        string access = await PhoneAccessTokenAsync();
        Assert.Equal(HttpStatusCode.OK, (await BearerAsync(access, "/api/guard/me")).StatusCode);

        using (IServiceScope scope = _factory!.Services.CreateScope())
        {
            Guid adminId = await MyIdAsync(await SignInAsync("admin", AdminPassword));
            await scope.ServiceProvider.GetRequiredService<Services.AccountSessions>().EndEverywhereAsync(adminId, null, null, "everywhere");
        }

        Assert.Equal(HttpStatusCode.Unauthorized, (await BearerAsync(access, "/api/guard/me")).StatusCode);
    }

    [Fact]
    public async Task Switched_off_personal_tokens_sign_no_one_in()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        (HttpStatusCode made, string body) = await admin.SendAsync(HttpMethod.Post, "/api/guard/me/tokens", new { name = "script", access = "write", days = 30 });
        Assert.Equal(HttpStatusCode.OK, made);
        string secret = JsonDocument.Parse(body).RootElement.GetProperty("secret").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await BearerAsync(secret, "/api/guard/me")).StatusCode);

        // The same site, started again with the feature off.
        await _factory!.DisposeAsync();
        Environment.SetEnvironmentVariable("Guard__Features__PersonalTokens", "false");
        _factory = new WebApplicationFactory<Program>();
        Assert.Equal(HttpStatusCode.Unauthorized, (await BearerAsync(secret, "/api/guard/me")).StatusCode);
    }

    [Fact]
    public async Task A_narrower_merge_right_sees_and_resumes_only_its_own_merges()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        Guid role = await CreateRoleAsync(admin, "merge-p",
            """{ "action": "merge", "subject": "Account", "conditions": { "username": { "$in": ["p1", "p2"] } } }""");
        Guid deduper = await CreateAccountAsync(admin, "deduper", "deduper@corp.example");
        await GrantAsync(admin, role, deduper, new { });
        Guid p1 = await CreateAccountAsync(admin, "p1", "p1@corp.example");
        Guid p2 = await CreateAccountAsync(admin, "p2", "p2@corp.example");
        Guid q1 = await CreateAccountAsync(admin, "q1", "q1@corp.example");
        Guid q2 = await CreateAccountAsync(admin, "q2", "q2@corp.example");

        Session d = await SignInAsync("deduper", Password);
        (HttpStatusCode ok, string mine) = await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{p1}/merge", new { survivorId = p2, confirm = "p1" });
        Assert.Equal(HttpStatusCode.OK, ok);
        Guid mineId = JsonDocument.Parse(mine).RootElement.GetProperty("id").GetGuid();
        (_, string other) = await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{q1}/merge", new { survivorId = q2, confirm = "q1" });
        Guid otherId = JsonDocument.Parse(other).RootElement.GetProperty("id").GetGuid();

        (_, string listed) = await d.SendAsync(HttpMethod.Get, "/api/guard/merges");
        Assert.Equal([mineId], JsonDocument.Parse(listed).RootElement.EnumerateArray().Select(m => m.GetProperty("id").GetGuid()));
        Assert.Equal(HttpStatusCode.OK, (await d.SendAsync(HttpMethod.Get, $"/api/guard/merges/{mineId}")).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await d.SendAsync(HttpMethod.Get, $"/api/guard/merges/{otherId}")).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await d.SendAsync(HttpMethod.Post, $"/api/guard/merges/{otherId}/resume")).Code);

        (_, string all) = await admin.SendAsync(HttpMethod.Get, "/api/guard/merges");
        Assert.Equal(2, JsonDocument.Parse(all).RootElement.GetArrayLength());
    }

    [Fact]
    public async Task Wrong_passwords_from_elsewhere_lock_no_one_out_nor_end_their_session()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        await CreateAccountAsync(admin, "ivan", "ivan@example.test");

        // Someone elsewhere runs out the name's tries from their address; the person still signs in from theirs.
        HttpClient attacker = Client("203.0.113.9");
        HttpResponseMessage[] guesses = [.. await Task.WhenAll(Enumerable.Range(0, 6).Select(i =>
            attacker.PostAsJsonAsync("/api/guard/session", new { username = "ivan", password = $"Wrong-Pass-{i:D4}" })))];
        Assert.Contains(guesses, r => r.StatusCode == HttpStatusCode.TooManyRequests);
        HttpClient own = Client("198.51.100.7");
        HttpResponseMessage signedIn = await own.PostAsJsonAsync("/api/guard/session", new { username = "ivan", password = Password });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        string prefix = new GuardCookieOptions().Csrf + "=";
        Session ivan = new(own, Uri.UnescapeDataString(signedIn.Headers.GetValues("Set-Cookie").First(c => c.StartsWith(prefix, StringComparison.Ordinal))[prefix.Length..].Split(';')[0]));

        // From the person's own address (a shared office's, say), the name blocked: a right step-up is refused for now,
        // and the session stays.
        HttpClient office = Client("198.51.100.7");
        for (int i = 0; i < 5; i++)
        {
            await office.PostAsJsonAsync("/api/guard/session", new { username = "ivan", password = $"Office-Guess-{i:D4}" });
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, (await ivan.SendAsync(HttpMethod.Post, "/api/guard/session/step-up", new { password = Password })).Code);
        Assert.Equal(HttpStatusCode.OK, (await ivan.SendAsync(HttpMethod.Get, "/api/guard/me")).Code);
    }

    [Fact]
    public async Task An_unknown_username_takes_as_long_as_a_wrong_password()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        await CreateAccountAsync(admin, "judy", "judy@example.test");
        _ = await Client("192.0.2.1").PostAsJsonAsync("/api/guard/session", new { username = "warm-up", password = "Wrong-Pass-0000" });

        async Task<double> MedianAsync(Func<int, string> username)
        {
            List<double> times = [];
            for (int i = 0; i < 4; i++)
            {
                Stopwatch watch = Stopwatch.StartNew();
                HttpResponseMessage refused = await Client($"192.0.2.{10 + i}").PostAsJsonAsync("/api/guard/session", new { username = username(i), password = "Wrong-Pass-1234" });
                watch.Stop();
                Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
                times.Add(watch.Elapsed.TotalMilliseconds);
            }

            return times.Order().ElementAt(times.Count / 2);
        }

        double known = await MedianAsync(_ => "judy");
        double unknown = await MedianAsync(i => $"nobody-{i}");
        Assert.True(unknown >= known * 0.5, $"unknown {unknown:F1} ms against known {known:F1} ms");
    }

    [Fact]
    public async Task The_admin_isnt_made_with_a_short_password()
    {
        Environment.SetEnvironmentVariable("Guard__Seed__AdminPassword", "short");
        try
        {
            await using WebApplicationFactory<Program> weak = new();
            Exception refused = Assert.ThrowsAny<Exception>(() => weak.CreateClient());
            Assert.Contains("AdminPassword", refused.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("Guard__Seed__AdminPassword", AdminPassword);
        }
    }

    [Fact]
    public async Task An_export_is_in_the_log_before_it_goes_out_and_how_it_ended_after()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(HttpMethod.Post, "/api/guard/me/data-export", new { })).Code);
        Assert.Equal([("privacy.export.self", "started"), ("privacy.export.ended", "finished")], await ExportEventsAsync());

        // A download that breaks part way: some of the data may have gone; the log has the export, and that it was cut off.
        await using WebApplicationFactory<Program> failing = _factory!.WithWebHostBuilder(host => host.ConfigureTestServices(s =>
        {
            s.AddTransient<IPersonalDataDeclarations, BreakingStore>();
            s.AddTransient<IPersonalDataExporter, BreakingStore>();
        }));
        HttpClient http = failing.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });
        HttpResponseMessage signedIn = await http.PostAsJsonAsync("/api/guard/session", new { username = "admin", password = AdminPassword });
        string prefix = new GuardCookieOptions().Csrf + "=";
        Session again = new(http, Uri.UnescapeDataString(signedIn.Headers.GetValues("Set-Cookie").First(c => c.StartsWith(prefix, StringComparison.Ordinal))[prefix.Length..].Split(';')[0]));
        try
        {
            await again.SendAsync(HttpMethod.Post, "/api/guard/me/data-export", new { });
        }
        catch (Exception)
        {
            // The download broke, as it should; what matters is what the log says.
        }

        Assert.Equal([("privacy.export.self", "started"), ("privacy.export.ended", "finished"), ("privacy.export.self", "started"), ("privacy.export.ended", "aborted")],
            await ExportEventsAsync());
    }

    [Fact]
    public async Task An_app_refreshes_only_when_it_asked_to()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        string clientId = await RegisterAppAsync();
        Assert.False((await AppTokensAsync(admin, clientId, "api")).TryGetProperty("refresh_token", out _));
        Assert.True((await AppTokensAsync(admin, clientId, "api offline_access")).TryGetProperty("refresh_token", out _));
    }

    [Fact]
    public async Task Switched_off_apps_leave_nothing_to_reach()
    {
        // Apps on, registering off: discovery names no registration endpoint.
        Environment.SetEnvironmentVariable("Guard__Features__ClientRegistration", "false");
        await using (WebApplicationFactory<Program> noRegistration = new())
        {
            JsonElement discovery = JsonDocument.Parse(await noRegistration.CreateClient().GetStringAsync("/.well-known/openid-configuration")).RootElement;
            Assert.False(discovery.TryGetProperty("registration_endpoint", out _));
            Assert.True(discovery.TryGetProperty("authorization_endpoint", out _));
        }

        Environment.SetEnvironmentVariable("Guard__Features__ClientRegistration", "true");
        Session admin = await SignInAsync("admin", AdminPassword);
        string access = (await AppTokensAsync(admin, await RegisterAppAsync(), "api")).GetProperty("access_token").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await BearerAsync(access, "/api/guard/me")).StatusCode);

        // The same site started again with apps off: no flow, nothing in discovery, and the app's token stops.
        await _factory!.DisposeAsync();
        Environment.SetEnvironmentVariable("Guard__Features__OAuthApps", "false");
        _factory = new WebApplicationFactory<Program>();
        JsonElement off = JsonDocument.Parse(await Client().GetStringAsync("/.well-known/openid-configuration")).RootElement;
        Assert.False(off.TryGetProperty("authorization_endpoint", out _));
        Assert.False(off.TryGetProperty("registration_endpoint", out _));
        Assert.Equal(HttpStatusCode.Unauthorized, (await BearerAsync(access, "/api/guard/me")).StatusCode);
    }

    /// <summary>A new site lets no app register itself until an admin allows it (Administration › Security): this one does.</summary>
    private async Task LetAppsRegisterAsync()
    {
        _ = Client();
        await using NpgsqlConnection connection = new($"{Server};Database={_database}");
        await connection.OpenAsync();
        await using NpgsqlCommand allow = new("UPDATE guard.security_settings SET \"AppsMayRegister\" = true", connection);
        Assert.Equal(1, await allow.ExecuteNonQueryAsync());
    }

    private async Task<string> RegisterAppAsync()
    {
        await LetAppsRegisterAsync();
        HttpResponseMessage registered = await Client().PostAsJsonAsync("/connect/register", new { client_name = "An app", redirect_uris = new[] { "https://app.example/cb" } });
        Assert.Equal(HttpStatusCode.Created, registered.StatusCode);
        return JsonDocument.Parse(await registered.Content.ReadAsStringAsync()).RootElement.GetProperty("client_id").GetString()!;
    }

    /// <summary>The person at the browser allows the app the scopes it asked for, and the app exchanges its code.</summary>
    private async Task<JsonElement> AppTokensAsync(Session person, string clientId, string scope)
    {
        string verifier = Verifier();
        using HttpRequestMessage allow = Allow(clientId, person.Csrf, scope, verifier);
        HttpResponseMessage allowed = await person.Http.SendAsync(allow);
        string code = System.Web.HttpUtility.ParseQueryString(allowed.Headers.Location!.Query)["code"]!;
        HttpResponseMessage tokens = await Client().PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["client_id"] = clientId, ["code"] = code, ["redirect_uri"] = "https://app.example/cb", ["code_verifier"] = verifier,
        }));
        string body = await tokens.Content.ReadAsStringAsync();
        Assert.True(tokens.IsSuccessStatusCode, body);
        return JsonDocument.Parse(body).RootElement.Clone();
    }

    /// <summary>The data exports in the security log, oldest first: their type and state.</summary>
    private async Task<List<(string, string)>> ExportEventsAsync()
    {
        await using NpgsqlConnection connection = new($"{Server};Database={_database}");
        await connection.OpenAsync();
        await using NpgsqlCommand read = new("""SELECT "Type", "Detail" FROM guard.security_events WHERE "Type" LIKE 'privacy.export.%' ORDER BY "Time" """, connection);
        await using NpgsqlDataReader rows = await read.ExecuteReaderAsync();
        List<(string, string)> events = [];
        while (await rows.ReadAsync())
        {
            events.Add((rows.GetString(0), JsonDocument.Parse(rows.GetString(1)).RootElement.GetProperty("state").GetString()!));
        }

        return events;
    }

    /// <summary>
    /// A host's store whose export stops part way, after some rows have gone out, as when the person downloading hangs up
    /// (a store that fails otherwise is only listed as missing, and the export finishes).
    /// </summary>
    private sealed class BreakingStore : IPersonalDataDeclarations, IPersonalDataExporter
    {
        public IReadOnlyList<PersonalDataStore> Stores { get; } =
        [
            new("test.breaking", "test", new LocalizedText("Breaking", "Breaking"), new LocalizedText("p", "p"), [], [], PersonalDataSubjects.Accounts,
                [PersonalDataKinds.Activity], PersonalDataKept.Forever, [], []),
        ];

        public IReadOnlyList<NonPersonalTable> NotPersonal { get; } = [];

        IReadOnlyList<string> IPersonalDataExporter.Stores { get; } = ["test.breaking"];

        public Task ExportAsync(IPersonalDataExport export, CancellationToken cancellationToken = default) =>
            export.WriteAsync("test.breaking", "rows", Rows(), cancellationToken);

        private static async IAsyncEnumerable<JsonObject> Rows()
        {
            for (int i = 0; i < 100; i++)
            {
                await Task.Yield();
                yield return new JsonObject { ["n"] = i };
            }

            throw new OperationCanceledException("The download was cut off part way.");
        }
    }

    [Fact]
    public async Task Redirects_stay_on_the_site()
    {
        // A handoff goes on to a page of this site only: another site's address, however written, ends at sign-in for "/".
        foreach ((string next, string expected) in new[]
        {
            ("//evil.example/x", "/login?next=%2F"), ("/\\evil.example", "/login?next=%2F"), ("https://evil.example", "/login?next=%2F"),
            ("/\tevil.example", "/login?next=%2F"), ("/projects/1", "/login?next=%2Fprojects%2F1"),
        })
        {
            HttpResponseMessage handoff = await Client().GetAsync($"/api/guard/session/handoff?code=unknown&next={Uri.EscapeDataString(next)}");
            Assert.Equal(HttpStatusCode.Redirect, handoff.StatusCode);
            Assert.Equal(expected, handoff.Headers.Location!.OriginalString);
        }

        // An app's sign-in goes to the site's own consent page, with the request's query and nothing else.
        Session admin = await SignInAsync("admin", AdminPassword);
        string clientId = await RegisterAppAsync();
        HttpResponseMessage asked = await admin.Http.GetAsync(
            $"/connect/authorize?client_id={clientId}&redirect_uri={Uri.EscapeDataString("https://app.example/cb")}&response_type=code&scope=api"
            + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=s");
        Assert.Equal(HttpStatusCode.Redirect, asked.StatusCode);
        Assert.StartsWith("/oauth/consent?", asked.Headers.Location!.OriginalString, StringComparison.Ordinal);
    }

    /// <summary>The host's phone app, public with the password grant, as a host registers it; and an access token from it for the admin.</summary>
    private async Task<string> PhoneAccessTokenAsync()
    {
        _ = Client();
        using (IServiceScope scope = _factory!.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "mobile",
                ClientType = ClientTypes.Public,
                Permissions =
                {
                    Permissions.Endpoints.Token, Permissions.GrantTypes.Password, Permissions.GrantTypes.RefreshToken,
                    Permissions.Prefixes.Scope + "api", Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                },
            });
        }

        HttpResponseMessage granted = await Client().PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password", ["client_id"] = "mobile", ["username"] = "admin", ["password"] = AdminPassword, ["scope"] = "api offline_access",
        }));
        return JsonDocument.Parse(await granted.Content.ReadAsStringAsync()).RootElement.GetProperty("access_token").GetString()!;
    }

    private async Task<HttpResponseMessage> BearerAsync(string token, string url)
    {
        using HttpRequestMessage request = new(HttpMethod.Get, url);
        request.Headers.Authorization = new("Bearer", token);
        return await Client().SendAsync(request);
    }

    /// <summary>The consent page's answer: allow, with write access, and the session's anti-forgery value when it has one.</summary>
    private static HttpRequestMessage Allow(string clientId, string? csrf) => Allow(clientId, csrf, "api offline_access", Verifier());

    private static string Verifier() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static HttpRequestMessage Allow(string clientId, string? csrf, string scope, string verifier)
    {
        Dictionary<string, string> form = new()
        {
            ["client_id"] = clientId, ["redirect_uri"] = "https://app.example/cb", ["response_type"] = "code", ["scope"] = scope,
            ["code_challenge"] = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
            ["code_challenge_method"] = "S256", ["state"] = "s", ["decision"] = "allow", ["access"] = "write",
        };
        if (csrf is not null)
        {
            form[new GuardCookieOptions().Csrf] = csrf;
        }

        return new HttpRequestMessage(HttpMethod.Post, "/connect/authorize") { Content = new FormUrlEncodedContent(form) };
    }

    /// <summary>The newest mail to the address in the pickup folder.</summary>
    private async Task<string> LastMailToAsync(string address)
    {
        foreach (string file in Directory.GetFiles(_mail, "*.eml").OrderDescending(StringComparer.Ordinal))
        {
            string mail = await File.ReadAllTextAsync(file);
            if (mail.Contains($"<{address}>", StringComparison.Ordinal))
            {
                return mail;
            }
        }

        throw new InvalidOperationException($"No mail to {address}.");
    }

    private static string TokenIn(string mail) => Uri.UnescapeDataString(Token().Match(mail).Groups[1].Value);

    [GeneratedRegex(@"token=([A-Za-z0-9_\-%.]+)", RegexOptions.None, 1000)]
    private static partial Regex Token();

    private sealed record Session(HttpClient Http, string Csrf)
    {
        public async Task<(HttpStatusCode Code, string Body)> SendAsync(HttpMethod method, string url, object? body = null)
        {
            using HttpRequestMessage request = new(method, url) { Content = body is null ? null : JsonContent.Create(body) };
            request.Headers.Add(CsrfHeader, Csrf);
            HttpResponseMessage response = await Http.SendAsync(request);
            return (response.StatusCode, await response.Content.ReadAsStringAsync());
        }
    }

    private HttpClient Client(string? ip = null)
    {
        HttpClient client = _factory!.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });
        if (ip is not null)
        {
            client.DefaultRequestHeaders.Add(TestIpHeader, ip);
        }

        return client;
    }

    /// <summary>Gives each request the client address its test header names, ahead of the host's own middleware.</summary>
    private sealed class TestAddresses : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, rest) =>
            {
                if (context.Request.Headers.TryGetValue(TestIpHeader, out Microsoft.Extensions.Primitives.StringValues ip))
                {
                    context.Connection.RemoteIpAddress = IPAddress.Parse(ip.ToString());
                }

                return rest(context);
            });
            next(app);
        };
    }

    private async Task<Session> SignInAsync(string username, string password)
    {
        HttpClient client = Client();
        HttpResponseMessage signedIn = await client.PostAsJsonAsync("/api/guard/session", new { username, password });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        string prefix = new GuardCookieOptions().Csrf + "=";
        string cookie = signedIn.Headers.GetValues("Set-Cookie").First(c => c.StartsWith(prefix, StringComparison.Ordinal));
        return new Session(client, Uri.UnescapeDataString(cookie[prefix.Length..].Split(';')[0]));
    }

    /// <summary>The second step a right password is asked for.</summary>
    private async Task<JsonElement> ChallengeAsync(string username)
    {
        HttpResponseMessage asked = await Client().PostAsJsonAsync("/api/guard/session", new { username, password = Password });
        Assert.Equal(HttpStatusCode.Unauthorized, asked.StatusCode);
        return JsonDocument.Parse(await asked.Content.ReadAsStringAsync()).RootElement.GetProperty("secondFactor").Clone();
    }

    private static async Task<Guid> MyIdAsync(Session session) =>
        JsonDocument.Parse((await session.SendAsync(HttpMethod.Get, "/api/guard/me")).Body).RootElement.GetProperty("account").GetProperty("id").GetGuid();

    private static async Task<Guid> CreateAccountAsync(Session admin, string username, string email)
    {
        (HttpStatusCode code, string body) = await admin.SendAsync(HttpMethod.Post, "/api/guard/accounts", new { username, displayName = username, email, password = Password });
        Assert.Equal(HttpStatusCode.OK, code);
        return JsonDocument.Parse(body).RootElement.GetProperty("id").GetGuid();
    }

    private static async Task AddToAdminsAsync(Session admin, Guid accountId)
    {
        (HttpStatusCode code, string body) = await admin.SendAsync(HttpMethod.Post, $"/api/guard/groups/{Admins}/members", new { accountId });
        Assert.True(code == HttpStatusCode.NoContent, body);
    }

    private static async Task<Guid> CreateRoleAsync(Session admin, string key, params string[] rules)
    {
        (HttpStatusCode code, string body) = await admin.SendAsync(HttpMethod.Post, "/api/guard/roles",
            new { key, name = key, description = (string?)null, rules = rules.Select(r => JsonDocument.Parse(r).RootElement).ToArray() });
        Assert.True(code == HttpStatusCode.OK, body);
        return JsonDocument.Parse(body).RootElement.GetProperty("id").GetGuid();
    }

    private static async Task GrantAsync(Session admin, Guid role, Guid account, object scope)
    {
        (HttpStatusCode code, string body) = await admin.SendAsync(HttpMethod.Post, $"/api/guard/roles/{role}/grants", new { principalType = "Account", principalId = account, scope });
        Assert.True(code == HttpStatusCode.OK, body);
    }
}
