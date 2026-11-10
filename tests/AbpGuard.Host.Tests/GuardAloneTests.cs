using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace AbpGuard.Host.Tests;

/// <summary>
/// Guard hosted alone, as another product (the marketplace) hosts it: the sample host on a database of its own
/// (ConnectionStrings:Guard), with Guard's defaults only. An admin opens sign-up, a person signs up, confirms the mailed
/// link from the pickup folder, signs in and reads /api/guard/me; a refused input is 400 and a switched-off feature 404;
/// a refusal is JSON whatever the client accepts.
/// Needs Postgres: localhost:5432 (postgres/postgres), or the server GUARD_TEST_POSTGRES names.
/// </summary>
[Collection(SampleHost.Collection)]
public sealed partial class GuardAloneTests : IAsyncLifetime
{
    /// <summary>The Postgres server the test makes its database on: GUARD_TEST_POSTGRES, else Postgres's image defaults.</summary>
    private static readonly string Server =
        Environment.GetEnvironmentVariable("GUARD_TEST_POSTGRES") is { Length: > 0 } server ? server : "Host=localhost;Port=5432;Username=postgres;Password=postgres";
    private const string AdminPassword = "Host-Admin-Pass-1";

    private readonly string _database = "guard_host_" + Guid.NewGuid().ToString("N")[..12];
    private readonly string _mail = Path.Combine(Path.GetTempPath(), "guard-host-mail-" + Guid.NewGuid().ToString("N"));
    private WebApplicationFactory<Program>? _factory;

    public Task InitializeAsync()
    {
        // The host reads its settings as it builds, so they're the process's environment for this test.
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");
        Environment.SetEnvironmentVariable("ConnectionStrings__Guard", $"{Server};Database={_database}");
        Environment.SetEnvironmentVariable("Guard__Seed__AdminPassword", AdminPassword);
        Environment.SetEnvironmentVariable("Guard__Messenger__PickupFolder", _mail);
        Environment.SetEnvironmentVariable("Guard__Features__Handoff", "true");
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
    }

    [Fact]
    public async Task Someone_signs_up_confirms_signs_in_and_is_known()
    {
        // Guard's defaults: sign-up starts closed.
        using (JsonDocument closed = JsonDocument.Parse(await Client().GetStringAsync("/api/guard/signup")))
        {
            Assert.False(closed.RootElement.GetProperty("enabled").GetBoolean());
        }

        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);

        // Sign-up is a site setting, off at first: an admin opens it for the internal directory.
        using HttpRequestMessage open = new(HttpMethod.Put, "/api/guard/signup/settings")
        {
            Content = JsonContent.Create(new { enabled = true, directoryId = "00000000-0000-0000-0000-00000000d001", emailDomains = Array.Empty<string>() }),
        };
        open.Headers.Add(CsrfHeader, csrf);
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(open)).StatusCode);

        // A switched-off feature (the sample has no directories to sync) has no endpoints.
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync("/api/guard/directories")).StatusCode);

        HttpClient visitor = Client();
        HttpResponseMessage refused = await visitor.PostAsJsonAsync("/api/guard/signup", new { email = "dana@example.test", displayName = "Dana", password = "short" });
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);

        HttpResponseMessage signedUp = await visitor.PostAsJsonAsync("/api/guard/signup", new { email = "dana@example.test", displayName = "Dana", password = "Dana-Pass-12345" });
        Assert.Equal(HttpStatusCode.NoContent, signedUp.StatusCode);
        string mail = await File.ReadAllTextAsync(Assert.Single(Directory.GetFiles(_mail, "*.eml")));
        Assert.Contains("To: \"Dana\" <dana@example.test>", mail);
        string token = Token().Match(mail).Groups[1].Value;

        HttpResponseMessage confirmed = await visitor.PostAsJsonAsync("/api/guard/signup/verify", new { token });
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);

        HttpClient dana = Client();
        await SignInAsync(dana, "dana@example.test", "Dana-Pass-12345");
        using JsonDocument me = JsonDocument.Parse(await dana.GetStringAsync("/api/guard/me"));
        Assert.Equal("dana@example.test", me.RootElement.GetProperty("account").GetProperty("username").GetString());
    }

    [Fact]
    public async Task A_refusal_is_json_whatever_the_client_accepts()
    {
        // The web's downloads fetch with Accept: */*; a refusal still answers with its JSON error and status.
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);
        using HttpRequestMessage record = new(HttpMethod.Get, "/api/guard/privacy/record?format=pdf");
        record.Headers.Add("Accept", "*/*");
        await AssertErrorAsync(await admin.SendAsync(record), HttpStatusCode.BadRequest, "bad_format");

        // A personal access token can't step up: the export's refusal (an action with no object result) is 403 JSON.
        using HttpRequestMessage create = new(HttpMethod.Post, "/api/guard/me/tokens")
        {
            Content = JsonContent.Create(new { name = "download", access = "write", projectIds = (Guid[]?)null, days = 7 }),
        };
        create.Headers.Add(CsrfHeader, csrf);
        HttpResponseMessage made = await admin.SendAsync(create);
        Assert.Equal(HttpStatusCode.OK, made.StatusCode);
        using JsonDocument token = JsonDocument.Parse(await made.Content.ReadAsStringAsync());
        HttpClient bearer = Client();
        using HttpRequestMessage export = new(HttpMethod.Post, "/api/guard/me/data-export") { Content = JsonContent.Create(new { }) };
        export.Headers.Add("Accept", "*/*");
        export.Headers.Authorization = new("Bearer", token.RootElement.GetProperty("secret").GetString());
        await AssertErrorAsync(await bearer.SendAsync(export), HttpStatusCode.Forbidden, GuardErrorCodes.Forbidden);

        // The phone's web view follows redirects: a refused handoff still goes to sign-in, not to a JSON error.
        using HttpRequestMessage handoff = new(HttpMethod.Get, "/api/guard/session/handoff?code=not-a-code&next=/projects");
        handoff.Headers.Add("Accept", "*/*");
        HttpResponseMessage redirected = await Client().SendAsync(handoff);
        Assert.Equal(HttpStatusCode.Redirect, redirected.StatusCode);
        Assert.Equal("/login?next=%2Fprojects", redirected.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task A_host_opens_sign_up_and_names_what_it_seeds_and_an_admins_choice_stays()
    {
        (string Key, string Value)[] host =
        [
            ("Guard__SignUp__Open", "true"), ("Guard__Seed__InternalDirectoryName", "Market accounts"), ("Guard__Seed__UsersGroupName", "market-users"),
            ("Guard__Seed__UsersGroupDescription", "Everyone with a market account."), ("Guard__Seed__AdminDisplayName", "Market admin"),
            ("Guard__Seed__AdminEmail", "admin@market.example"),
        ];
        try
        {
            foreach ((string key, string value) in host)
            {
                Environment.SetEnvironmentVariable(key, value);
            }

            await using (WebApplicationFactory<Program> first = new())
            {
                HttpClient visitor = first.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
                using JsonDocument open = JsonDocument.Parse(await visitor.GetStringAsync("/api/guard/signup"));
                Assert.True(open.RootElement.GetProperty("enabled").GetBoolean());

                await using NpgsqlConnection connection = new($"{Server};Database={_database}");
                await connection.OpenAsync();
                await using NpgsqlCommand names = new(
                    "SELECT (SELECT \"Name\" FROM guard.directories WHERE \"Id\" = '00000000-0000-0000-0000-00000000d001') || '|' || "
                    + "(SELECT \"Name\" || '|' || coalesce(\"Description\", '') FROM guard.groups WHERE \"Name\" = 'market-users') || '|' || "
                    + "(SELECT \"DisplayName\" || '|' || \"Email\" FROM guard.accounts WHERE \"Username\" = 'admin')", connection);
                Assert.Equal("Market accounts|market-users|Everyone with a market account.|Market admin|admin@market.example", await names.ExecuteScalarAsync());

                // An admin closes it: that choice stays when the site starts again with the same settings.
                HttpClient admin = first.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });
                string csrf = await SignInAsync(admin, "admin", AdminPassword);
                using HttpRequestMessage close = new(HttpMethod.Put, "/api/guard/signup/settings")
                {
                    Content = JsonContent.Create(new { enabled = false, directoryId = (Guid?)null, emailDomains = Array.Empty<string>() }),
                };
                close.Headers.Add(CsrfHeader, csrf);
                Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(close)).StatusCode);
            }

            await using WebApplicationFactory<Program> again = new();
            using JsonDocument closed = JsonDocument.Parse(await again.CreateClient().GetStringAsync("/api/guard/signup"));
            Assert.False(closed.RootElement.GetProperty("enabled").GetBoolean());
        }
        finally
        {
            foreach ((string key, _) in host)
            {
                Environment.SetEnvironmentVariable(key, null);
            }
        }
    }

    [Fact]
    public async Task The_authenticator_names_the_product_and_the_second_step_lists_recovery_when_the_host_says()
    {
        (string Key, string Value)[] host = [("Guard__TwoFactor__ListsRecovery", "true"), ("Guard__Texts__ProductName__en", "Market")];
        try
        {
            foreach ((string key, string value) in host)
            {
                Environment.SetEnvironmentVariable(key, value);
            }

            await using WebApplicationFactory<Program> factory = new();
            HttpClient admin = factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });
            string csrf = await SignInAsync(admin, "admin", AdminPassword);
            using HttpRequestMessage start = new(HttpMethod.Post, "/api/guard/me/second-factors/app");
            start.Headers.Add(CsrfHeader, csrf);
            HttpResponseMessage started = await admin.SendAsync(start);
            Assert.Equal(HttpStatusCode.OK, started.StatusCode);
            using JsonDocument app = JsonDocument.Parse(await started.Content.ReadAsStringAsync());
            Assert.Contains("issuer=Market%20%28localhost%29", app.RootElement.GetProperty("address").GetString());

            string code = Services.TwoFactor.Totp.Code(Services.TwoFactor.Totp.FromBase32(app.RootElement.GetProperty("secret").GetString()!),
                Services.TwoFactor.Totp.StepAt(DateTimeOffset.UtcNow));
            using HttpRequestMessage confirm = new(HttpMethod.Post, "/api/guard/me/second-factors/app/confirm") { Content = JsonContent.Create(new { code }) };
            confirm.Headers.Add(CsrfHeader, csrf);
            Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(confirm)).StatusCode);

            // Signing in again asks for the second step: the app, and the recovery codes the person now has.
            HttpResponseMessage asked = await factory.CreateClient().PostAsJsonAsync("/api/guard/session", new { username = "admin", password = AdminPassword });
            Assert.Equal(HttpStatusCode.Unauthorized, asked.StatusCode);
            using JsonDocument body = JsonDocument.Parse(await asked.Content.ReadAsStringAsync());
            Assert.Equal(["app", "recovery"], body.RootElement.GetProperty("secondFactor").GetProperty("methods").EnumerateArray().Select(m => m.GetString()!).ToArray());
        }
        finally
        {
            foreach ((string key, _) in host)
            {
                Environment.SetEnvironmentVariable(key, null);
            }
        }
    }

    [Fact]
    public async Task The_names_Guard_writes_are_the_hosts()
    {
        // A host names its anti-forgery header and its tokens' prefix (Guard:Names): Guard asks for and recognises those.
        (string Key, string Value)[] host = [("Guard__Names__CsrfHeader", "X-Acme-Csrf"), ("Guard__Names__PersonalTokenPrefix", "acme_pat_")];
        try
        {
            foreach ((string key, string value) in host)
            {
                Environment.SetEnvironmentVariable(key, value);
            }

            await using WebApplicationFactory<Program> factory = new();
            HttpClient admin = factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });
            string csrf = await SignInAsync(admin, "admin", AdminPassword);
            object body = new { name = "acme", access = "read", projectIds = (Guid[]?)null, days = 7 };
            using HttpRequestMessage refused = new(HttpMethod.Post, "/api/guard/me/tokens") { Content = JsonContent.Create(body) };
            refused.Headers.Add(CsrfHeader, csrf);
            Assert.Equal(HttpStatusCode.Forbidden, (await admin.SendAsync(refused)).StatusCode);

            using HttpRequestMessage create = new(HttpMethod.Post, "/api/guard/me/tokens") { Content = JsonContent.Create(body) };
            create.Headers.Add("X-Acme-Csrf", csrf);
            HttpResponseMessage made = await admin.SendAsync(create);
            Assert.Equal(HttpStatusCode.OK, made.StatusCode);
            using JsonDocument token = JsonDocument.Parse(await made.Content.ReadAsStringAsync());
            string secret = token.RootElement.GetProperty("secret").GetString()!;
            Assert.StartsWith("acme_pat_", secret);

            using HttpRequestMessage me = new(HttpMethod.Get, "/api/guard/me");
            me.Headers.Authorization = new("Bearer", secret);
            Assert.Equal(HttpStatusCode.OK, (await factory.CreateClient().SendAsync(me)).StatusCode);

            // The host moves to a new prefix and keeps the old one accepted: the token made before still signs in.
            Environment.SetEnvironmentVariable("Guard__Names__PersonalTokenPrefix", "acme2_pat_");
            Environment.SetEnvironmentVariable("Guard__Names__AcceptedTokenPrefixes__0", "acme_pat_");
            await using WebApplicationFactory<Program> moved = new();
            using HttpRequestMessage again = new(HttpMethod.Get, "/api/guard/me");
            again.Headers.Authorization = new("Bearer", secret);
            Assert.Equal(HttpStatusCode.OK, (await moved.CreateClient().SendAsync(again)).StatusCode);
        }
        finally
        {
            foreach ((string key, _) in host)
            {
                Environment.SetEnvironmentVariable(key, null);
            }

            Environment.SetEnvironmentVariable("Guard__Names__AcceptedTokenPrefixes__0", null);
        }
    }

    [Fact]
    public void A_code_the_host_mapped_keeps_its_status_and_a_refused_input_is_400()
    {
        // The host maps its own code to 403, as the marketplace does: Guard's finder keeps it, and still answers 400 for
        // input a rule refused.
        using WebApplicationFactory<Program> host = _factory!.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.Configure<Volo.Abp.AspNetCore.ExceptionHandling.AbpExceptionHttpStatusCodeOptions>(o => o.Map("Host:Forbidden", HttpStatusCode.Forbidden))));
        using IServiceScope scope = host.Services.CreateScope();
        Volo.Abp.AspNetCore.ExceptionHandling.IHttpExceptionStatusCodeFinder finder =
            scope.ServiceProvider.GetRequiredService<Volo.Abp.AspNetCore.ExceptionHandling.IHttpExceptionStatusCodeFinder>();
        Microsoft.AspNetCore.Http.DefaultHttpContext http = new();

        Assert.Equal(HttpStatusCode.Forbidden, finder.GetStatusCode(http, new Volo.Abp.BusinessException("Host:Forbidden")));
        Assert.Equal(HttpStatusCode.BadRequest, finder.GetStatusCode(http, new Volo.Abp.UserFriendlyException("Passwords need at least 10 characters.")));
        Assert.Equal(HttpStatusCode.Forbidden, finder.GetStatusCode(http, new Volo.Abp.UserFriendlyException("Confirm.", GuardErrorCodes.StepUpRequired)));
    }

    [Fact]
    public async Task The_host_makes_a_service_account_and_its_events_commit_with_it()
    {
        // The host sets nothing about ABP's clock: Guard keeps it in UTC, which its outbox and Postgres need.
        _ = Client();
        using (IServiceScope scope = _factory!.Services.CreateScope())
        {
            Assert.Equal(DateTimeKind.Utc, scope.ServiceProvider.GetRequiredService<Volo.Abp.Timing.IClock>().Kind);
            AccountInfo made = await scope.ServiceProvider.GetRequiredService<IServiceAccounts>().CreateAsync(new ServiceAccountInput("robot") { DisplayName = "Robot" });
            Assert.Equal("robot", made.Username);
        }

        // The account, its audit entry and its event are one unit of work: all three are there.
        await using NpgsqlConnection connection = new($"{Server};Database={_database}");
        await connection.OpenAsync();
        await using NpgsqlCommand count = new(
            "SELECT (SELECT count(*) FROM guard.accounts WHERE \"Username\" = 'robot') + (SELECT count(*) FROM guard.security_events WHERE \"Type\" = 'account.created' AND \"TargetName\" = 'robot')"
            + " + (SELECT count(*) FROM guard.\"AbpEventOutbox\" WHERE \"EventName\" LIKE '%AccountCreated%')", connection);
        Assert.Equal(3L, (long)(await count.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task The_host_gives_a_service_account_a_token_and_takes_it_back_but_not_an_agents()
    {
        HttpClient http = Client();
        using IServiceScope scope = _factory!.Services.CreateScope();
        IServiceAccounts accounts = scope.ServiceProvider.GetRequiredService<IServiceAccounts>();
        AccountInfo robot = await accounts.CreateAsync(new ServiceAccountInput("robot"));
        AccountInfo agent = await accounts.CreateAsync(new ServiceAccountInput("helper") { Agent = true });

        NewServiceAccountToken made = await accounts.CreateTokenAsync(new ServiceAccountTokenInput(robot.Id, "deploys", 7) { Access = "read" });
        Assert.StartsWith(made.Token.Prefix, made.Secret);
        Assert.Equal(("deploys", "read", true), (made.Token.Name, made.Token.Access, made.Token.Active));
        using HttpRequestMessage me = new(HttpMethod.Get, "/api/guard/me");
        me.Headers.Authorization = new("Bearer", made.Secret);
        HttpResponseMessage known = await http.SendAsync(me);
        Assert.Equal(HttpStatusCode.OK, known.StatusCode);
        using (JsonDocument body = JsonDocument.Parse(await known.Content.ReadAsStringAsync()))
        {
            Assert.Equal("robot", body.RootElement.GetProperty("account").GetProperty("username").GetString());
        }

        Assert.Single(await accounts.ListTokensAsync(robot.Id));
        await Assert.ThrowsAsync<Volo.Abp.UserFriendlyException>(() => accounts.CreateTokenAsync(new ServiceAccountTokenInput(agent.Id, "no", 7)));
        await Assert.ThrowsAsync<Volo.Abp.UserFriendlyException>(() => accounts.CreateTokenAsync(new ServiceAccountTokenInput(robot.Id, "", 7)));

        await accounts.RevokeTokenAsync(robot.Id, made.Token.Id);
        using HttpRequestMessage again = new(HttpMethod.Get, "/api/guard/me");
        again.Headers.Authorization = new("Bearer", made.Secret);
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.SendAsync(again)).StatusCode);
        Assert.Empty(await accounts.ListTokensAsync(robot.Id));
        Assert.Single(await accounts.ListTokensAsync(robot.Id, all: true));

        // Audited as the admin page's are.
        await using NpgsqlConnection connection = new($"{Server};Database={_database}");
        await connection.OpenAsync();
        await using NpgsqlCommand audit = new("SELECT string_agg(\"Type\", ',' ORDER BY \"Time\") FROM guard.security_events WHERE \"TargetName\" = 'robot' AND \"Type\" LIKE 'token.%'", connection);
        Assert.Equal("token.created,token.revoked", await audit.ExecuteScalarAsync());
    }

    [Fact]
    public async Task A_ticket_whose_step_is_a_sent_code_cant_set_up_an_app_in_its_place()
    {
        // Erin's group requires a second factor and the site may mail codes; she has no app.
        (HttpClient admin, string csrf) = await EmailCodesRequiredForAsync("erin", "Erin-Pass-12345");

        // Her step is the mailed code: the password's ticket can't put an app of its own there, nor pass without a code.
        (string ticket, bool enrol, string[] methods) = await ChallengeAsync("erin", "Erin-Pass-12345");
        Assert.False(enrol);
        Assert.Equal(["email"], methods);
        HttpClient visitor = Client();
        await AssertErrorAsync(await visitor.PostAsJsonAsync("/api/guard/second-factor/enrol/app", new { ticket }), HttpStatusCode.Unauthorized, "ticket_expired");
        await AssertErrorAsync(await visitor.PostAsJsonAsync("/api/guard/second-factor/enrol/app/confirm", new { ticket, code = "000000" }), HttpStatusCode.Unauthorized, "ticket_expired");
        Assert.False((await visitor.PostAsJsonAsync("/api/guard/session/second-factor", new { ticket, method = (string?)null, code = (string?)null })).IsSuccessStatusCode);

        // With no code the site can send, the step is to set one up: the same ticket route sets the app up and passes.
        Assert.True((await SendAsync(admin, csrf, HttpMethod.Put, "/api/guard/security/second-factor", new { methods = Array.Empty<string>() })).IsSuccessStatusCode);
        (ticket, enrol, methods) = await ChallengeAsync("erin", "Erin-Pass-12345");
        Assert.True(enrol);
        Assert.Empty(methods);
        HttpResponseMessage started = await visitor.PostAsJsonAsync("/api/guard/second-factor/enrol/app", new { ticket });
        Assert.Equal(HttpStatusCode.OK, started.StatusCode);
        using JsonDocument app = JsonDocument.Parse(await started.Content.ReadAsStringAsync());
        string code = Services.TwoFactor.Totp.Code(Services.TwoFactor.Totp.FromBase32(app.RootElement.GetProperty("secret").GetString()!),
            Services.TwoFactor.Totp.StepAt(DateTimeOffset.UtcNow));
        Assert.Equal(HttpStatusCode.OK, (await visitor.PostAsJsonAsync("/api/guard/second-factor/enrol/app/confirm", new { ticket, code })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await visitor.PostAsJsonAsync("/api/guard/session/second-factor", new { ticket, method = (string?)null, code = (string?)null })).StatusCode);
    }

    [Fact]
    public async Task A_sign_in_sends_three_codes_and_takes_five_wrong_ones()
    {
        await EmailCodesRequiredForAsync("ivy", "Ivy-Pass-12345");
        (string ticket, _, _) = await ChallengeAsync("ivy", "Ivy-Pass-12345");
        HttpClient visitor = Client();
        for (int i = 0; i < 3; i++)
        {
            Assert.Equal(HttpStatusCode.OK, (await visitor.PostAsJsonAsync("/api/guard/second-factor/send", new { ticket, method = "email" })).StatusCode);
        }

        await AssertErrorAsync(await visitor.PostAsJsonAsync("/api/guard/second-factor/send", new { ticket, method = "email" }), HttpStatusCode.TooManyRequests, "too_many_attempts");

        for (int i = 0; i < 5; i++)
        {
            await AssertErrorAsync(await visitor.PostAsJsonAsync("/api/guard/session/second-factor", new { ticket, method = "email", code = "000000" }),
                HttpStatusCode.BadRequest, "second_factor_failed");
        }

        await AssertErrorAsync(await visitor.PostAsJsonAsync("/api/guard/session/second-factor", new { ticket, method = "email", code = "000000" }), HttpStatusCode.Unauthorized, "ticket_expired");
    }

    [Fact]
    public async Task A_password_reset_ends_the_sessions_and_tokens_the_old_password_made()
    {
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/accounts",
            new { username = "fern", displayName = "Fern", email = "fern@example.test", password = "Fern-Pass-12345" })).StatusCode);

        // Fern is signed in in a browser and has an access token.
        HttpClient browser = Client();
        string fernCsrf = await SignInAsync(browser, "fern", "Fern-Pass-12345");
        HttpResponseMessage made = await SendAsync(browser, fernCsrf, HttpMethod.Post, "/api/guard/me/tokens", new { name = "cli", access = "write", projectIds = (Guid[]?)null, days = 7 });
        Assert.Equal(HttpStatusCode.OK, made.StatusCode);
        string secret;
        using (JsonDocument token = JsonDocument.Parse(await made.Content.ReadAsStringAsync()))
        {
            secret = token.RootElement.GetProperty("secret").GetString()!;
        }

        // She resets her password from the mailed link.
        Assert.Equal(HttpStatusCode.NoContent, (await Client().PostAsJsonAsync("/api/guard/password/forgot", new { email = "fern@example.test" })).StatusCode);
        string link = await MailTokenAsync("fern@example.test");
        Assert.True((await Client().PostAsJsonAsync("/api/guard/password/reset", new { token = link, password = "Fern-New-Pass-123" })).IsSuccessStatusCode);

        // What the old password signed in no longer works; the new password does.
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/guard/me")).StatusCode);
        using HttpRequestMessage me = new(HttpMethod.Get, "/api/guard/me");
        me.Headers.Authorization = new("Bearer", secret);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Client().SendAsync(me)).StatusCode);
        await SignInAsync(Client(), "fern", "Fern-New-Pass-123");
    }

    [Fact]
    public async Task Signing_up_again_replaces_the_earlier_link()
    {
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, csrf, HttpMethod.Put, "/api/guard/signup/settings",
            new { enabled = true, directoryId = "00000000-0000-0000-0000-00000000d001", emailDomains = Array.Empty<string>() })).StatusCode);

        // Two sign-ups for the same address before it's confirmed: only the latest link confirms, with its own password.
        Assert.Equal(HttpStatusCode.NoContent, (await Client().PostAsJsonAsync("/api/guard/signup", new { email = "gail@example.test", displayName = "Gail", password = "Gail-First-12345" })).StatusCode);
        string first = await MailTokenAsync("gail@example.test");
        Assert.Equal(HttpStatusCode.NoContent, (await Client().PostAsJsonAsync("/api/guard/signup", new { email = "gail@example.test", displayName = "Gail", password = "Gail-Second-1234" })).StatusCode);
        string second = await MailTokenAsync("gail@example.test");
        Assert.NotEqual(first, second);

        Assert.Equal(HttpStatusCode.BadRequest, (await Client().PostAsJsonAsync("/api/guard/signup/verify", new { token = first })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Client().PostAsJsonAsync("/api/guard/signup/verify", new { token = second })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Client().PostAsJsonAsync("/api/guard/session", new { username = "gail@example.test", password = "Gail-First-12345" })).StatusCode);
        await SignInAsync(Client(), "gail@example.test", "Gail-Second-1234");
    }

    [Fact]
    public async Task Wrong_passwords_for_a_merged_account_count_toward_the_limit()
    {
        Environment.SetEnvironmentVariable("Guard__Features__Merges", "true");
        try
        {
            HttpClient admin = Client();
            string csrf = await SignInAsync(admin, "admin", AdminPassword);
            Guid old = await IdAsync(await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/accounts",
                new { username = "hal-old", displayName = "Hal", email = (string?)null, password = "Hal-Old-Pass-123" }));
            Guid kept = await IdAsync(await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/accounts",
                new { username = "hal", displayName = "Hal", email = (string?)null, password = "Hal-New-Pass-123" }));
            Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, csrf, HttpMethod.Post, $"/api/guard/accounts/{old}/merge", new { survivorId = kept, confirm = "hal-old" })).StatusCode);

            // The merged account's own password still points to the survivor; wrong ones are limited like any sign-in's.
            for (int i = 0; i < 5; i++)
            {
                await AssertErrorAsync(await Client().PostAsJsonAsync("/api/guard/session", new { username = "hal-old", password = $"wrong-{i}-password" }),
                    HttpStatusCode.Unauthorized, "invalid_credentials");
            }

            Assert.Equal(HttpStatusCode.TooManyRequests, (await Client().PostAsJsonAsync("/api/guard/session", new { username = "hal-old", password = "Hal-Old-Pass-123" })).StatusCode);
        }
        finally
        {
            Environment.SetEnvironmentVariable("Guard__Features__Merges", null);
        }
    }

    /// <summary>
    /// A person ({username}@example.test) in a group that requires a second factor, on a site that mails codes: the
    /// admin's client and its anti-forgery value.
    /// </summary>
    private async Task<(HttpClient Admin, string Csrf)> EmailCodesRequiredForAsync(string username, string password)
    {
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);
        Guid person = await IdAsync(await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/accounts",
            new { username, displayName = username, email = $"{username}@example.test", password }));
        Guid group = await IdAsync(await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/groups", new { name = $"needs-two-factor-{username}", description = (string?)null, directoryId = (Guid?)null }));
        Assert.True((await SendAsync(admin, csrf, HttpMethod.Post, $"/api/guard/groups/{group}/members", new { accountId = person, groupId = (Guid?)null })).IsSuccessStatusCode);
        Assert.True((await SendAsync(admin, csrf, HttpMethod.Put, $"/api/guard/groups/{group}/two-factor", new { mode = "required" })).IsSuccessStatusCode);
        Assert.True((await SendAsync(admin, csrf, HttpMethod.Put, "/api/guard/security/second-factor", new { methods = new[] { "email" } })).IsSuccessStatusCode);
        return (admin, csrf);
    }

    /// <summary>The token in the newest mail to the address in the pickup folder.</summary>
    private async Task<string> MailTokenAsync(string address)
    {
        foreach (string file in Directory.GetFiles(_mail, "*.eml").OrderDescending(StringComparer.Ordinal))
        {
            string mail = await File.ReadAllTextAsync(file);
            if (mail.Contains($"<{address}>", StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(Token().Match(mail).Groups[1].Value);
            }
        }

        throw new InvalidOperationException($"No mail to {address}.");
    }

    /// <summary>Signs in with a password a second step is asked for: the ticket, whether it's to set one up, and the methods.</summary>
    private async Task<(string Ticket, bool Enrol, string[] Methods)> ChallengeAsync(string username, string password)
    {
        HttpResponseMessage asked = await Client().PostAsJsonAsync("/api/guard/session", new { username, password });
        Assert.Equal(HttpStatusCode.Unauthorized, asked.StatusCode);
        using JsonDocument body = JsonDocument.Parse(await asked.Content.ReadAsStringAsync());
        JsonElement step = body.RootElement.GetProperty("secondFactor");
        return (step.GetProperty("ticket").GetString()!, step.GetProperty("enrol").GetBoolean(),
            step.GetProperty("methods").EnumerateArray().Select(m => m.GetString()!).ToArray());
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
        Assert.Equal(status, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(code, body.RootElement.GetProperty("error").GetProperty("code").GetString());
    }

    private HttpClient Client() => _factory!.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });

    /// <summary>The anti-forgery header, Guard's default name, as the sample host leaves it.</summary>
    private static readonly string CsrfHeader = new GuardNames().CsrfHeader;

    /// <summary>Signs in with the web's session cookie; the anti-forgery value the page would read from its cookie.</summary>
    private static async Task<string> SignInAsync(HttpClient client, string username, string password, string? csrfCookie = null)
    {
        HttpResponseMessage signedIn = await client.PostAsJsonAsync("/api/guard/session", new { username, password });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        string prefix = (csrfCookie ?? new GuardCookieOptions().Csrf) + "=";
        string cookie = signedIn.Headers.GetValues("Set-Cookie").First(c => c.StartsWith(prefix, StringComparison.Ordinal));
        return Uri.UnescapeDataString(cookie[prefix.Length..].Split(';')[0]);
    }

    [GeneratedRegex(@"token=([A-Za-z0-9_\-%.]+)", RegexOptions.None, 1000)]
    private static partial Regex Token();
}
