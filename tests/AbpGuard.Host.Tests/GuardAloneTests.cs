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
    public async Task A_token_under_former_names_is_read_by_todays_before_its_claims_are_and_a_stray_one_is_refused()
    {
        // Wired into the host's validation, after OpenIddict has validated the access token and before the ticket is built
        // that the current user and the limits are read from (GuardNames.Former).
        OpenIddict.Validation.OpenIddictValidationOptions validation = _factory!.Services
            .GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<OpenIddict.Validation.OpenIddictValidationOptions>>().CurrentValue;
        OpenIddict.Validation.OpenIddictValidationHandlerDescriptor wired = Assert.Single(validation.Handlers,
            h => h.ServiceDescriptor.ServiceType == typeof(Services.TokenNamesOfToday));
        Assert.True(wired.Order > OpenIddict.Validation.OpenIddictValidationHandlers.ValidateAccessToken.Descriptor.Order);

        Guid project = Guid.NewGuid();
        OpenIddict.Validation.OpenIddictValidationEvents.ProcessAuthenticationContext Context(params (string Type, string Value)[] claims) =>
            new(new OpenIddict.Validation.OpenIddictValidationTransaction { Options = validation, Logger = Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance })
            {
                AccessTokenPrincipal = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
                    claims.Select(c => new System.Security.Claims.Claim(c.Type, c.Value)), "Bearer")),
            };

        // The host's own handler, as the host resolves it: a site with no former names refuses a stray limit claim.
        using IServiceScope scope = _factory.Services.CreateScope();
        Services.TokenNamesOfToday hosts = scope.ServiceProvider.GetRequiredService<Services.TokenNamesOfToday>();
        var stray = Context(("sub", Guid.NewGuid().ToString()), ("old_token", Guid.NewGuid().ToString()), ("old_token_project", project.ToString()));
        await hosts.HandleAsync(stray);
        Assert.True(stray.IsRejected);
        Assert.Equal(OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidToken, stray.Error);

        // A site that names its former names: the old token reads with today's, its project limit kept.
        GuardNames renamed = new() { Former = new FormerTokenNames { TokenClaim = "old_token", TokenProjectClaim = "old_token_project" } };
        var old = Context(("sub", Guid.NewGuid().ToString()), ("old_token", Guid.NewGuid().ToString()), ("old_token_project", project.ToString()));
        await new Services.TokenNamesOfToday(Microsoft.Extensions.Options.Options.Create(renamed)).HandleAsync(old);
        Assert.False(old.IsRejected);
        Assert.Equal(project.ToString(), old.AccessTokenPrincipal!.FindFirst(renamed.TokenProjectClaim)?.Value);
        Assert.Null(old.AccessTokenPrincipal.FindFirst("old_token_project"));
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
    public async Task The_host_names_a_service_account_by_language_and_renames_it_but_never_a_person()
    {
        _ = Client();
        using IServiceScope scope = _factory!.Services.CreateScope();
        IServiceAccounts accounts = scope.ServiceProvider.GetRequiredService<IServiceAccounts>();
        IAccountLookup lookup = scope.ServiceProvider.GetRequiredService<IAccountLookup>();

        // Made with its names: the name as written (English) and the others by language, as a person's.
        AccountInfo made = await accounts.CreateAsync(new ServiceAccountInput("triage")
        {
            DisplayName = "Triage", Agent = true, DisplayNames = new Dictionary<string, string> { ["ar"] = "الفرز" },
        });
        Assert.Equal(("Triage", "الفرز"), (made.DisplayName, made.DisplayNames!["ar"]));
        await Assert.ThrowsAsync<Volo.Abp.UserFriendlyException>(() => accounts.CreateAsync(new ServiceAccountInput("nameless")
        {
            DisplayNames = new Dictionary<string, string> { ["ar"] = "بلا اسم" },
        }));

        // Renamed: both names follow, audited and told once.
        AccountInfo renamed = await accounts.RenameAsync(made.Id, "Desk triage", new Dictionary<string, string> { ["ar"] = "فرز المكتب" });
        Assert.Equal(("Desk triage", "فرز المكتب"), (renamed.DisplayName, renamed.DisplayNames!["ar"]));
        AccountInfo stored = (await lookup.GetAsync(made.Id))!;
        Assert.Equal(("Desk triage", "فرز المكتب"), (stored.DisplayName, stored.DisplayNames!["ar"]));

        // The same names again change nothing: no second audit entry, no second event.
        await accounts.RenameAsync(made.Id, "Desk triage", new Dictionary<string, string> { ["ar"] = "فرز المكتب" });
        await using NpgsqlConnection connection = new($"{Server};Database={_database}");
        await connection.OpenAsync();
        await using NpgsqlCommand count = new(
            "SELECT (SELECT count(*) FROM guard.security_events WHERE \"Type\" = 'account.renamed' AND \"TargetName\" = 'triage')"
            + " + (SELECT count(*) FROM guard.\"AbpEventOutbox\" WHERE \"EventName\" LIKE '%AccountChanged%')", connection);
        Assert.Equal(2L, (long)(await count.ExecuteScalarAsync())!);

        // Never a person's account, and never a reserved name.
        AccountInfo admin = (await lookup.FindByUsernameAsync("admin"))!;
        Volo.Abp.UserFriendlyException person = await Assert.ThrowsAsync<Volo.Abp.UserFriendlyException>(() => accounts.RenameAsync(admin.Id, "Someone else", null));
        Assert.Contains("Only a service account", person.Message);
        await Assert.ThrowsAsync<Volo.Abp.UserFriendlyException>(() => accounts.RenameAsync(made.Id, "Former person 12", null));
        await Assert.ThrowsAsync<Volo.Abp.UserFriendlyException>(() =>
            accounts.RenameAsync(made.Id, "Desk triage", new Dictionary<string, string> { ["ar"] = "Former person 12" }));
    }

    [Fact]
    public async Task The_host_gives_a_service_account_a_picture_on_the_site_but_never_a_person()
    {
        _ = Client();
        using IServiceScope scope = _factory!.Services.CreateScope();
        IServiceAccounts accounts = scope.ServiceProvider.GetRequiredService<IServiceAccounts>();
        IAccountLookup lookup = scope.ServiceProvider.GetRequiredService<IAccountLookup>();
        AccountInfo made = await accounts.CreateAsync(new ServiceAccountInput("designer") { DisplayName = "Designer", Agent = true });
        Assert.Null(made.Picture);

        // Set, and read back wherever the account is looked up.
        AccountInfo set = await accounts.SetPictureAsync(made.Id, "/api/pictures/builtin-owl.png");
        Assert.Equal("/api/pictures/builtin-owl.png", set.Picture);
        Assert.Equal("/api/pictures/builtin-owl.png", (await lookup.GetAsync(made.Id))!.Picture);

        // The same again changes nothing: one audit entry and one event, then cleared: a second of each.
        await accounts.SetPictureAsync(made.Id, "/api/pictures/builtin-owl.png");
        await using NpgsqlConnection connection = new($"{Server};Database={_database}");
        await connection.OpenAsync();
        async Task<long> CountAsync()
        {
            await using NpgsqlCommand count = new(
                "SELECT (SELECT count(*) FROM guard.security_events WHERE \"Type\" = 'account.picture' AND \"TargetName\" = 'designer')"
                + " + (SELECT count(*) FROM guard.\"AbpEventOutbox\" WHERE \"EventName\" LIKE '%AccountChanged%')", connection);
            return (long)(await count.ExecuteScalarAsync())!;
        }

        Assert.Equal(2L, await CountAsync());
        Assert.Null((await accounts.SetPictureAsync(made.Id, null)).Picture);
        Assert.Null((await lookup.GetAsync(made.Id))!.Picture);
        Assert.Equal(4L, await CountAsync());

        // Never an address elsewhere, and never a person's account.
        foreach (string elsewhere in new[] { "//host/x.png", "/\\host/x.png", "https://host/x.png", "javascript:alert(1)", "data:image/png;base64,AAAA", "/api/../x.png" })
        {
            await Assert.ThrowsAsync<Volo.Abp.UserFriendlyException>(() => accounts.SetPictureAsync(made.Id, elsewhere));
        }

        AccountInfo admin = (await lookup.FindByUsernameAsync("admin"))!;
        Volo.Abp.UserFriendlyException person = await Assert.ThrowsAsync<Volo.Abp.UserFriendlyException>(() => accounts.SetPictureAsync(admin.Id, "/api/pictures/builtin-owl.png"));
        Assert.Contains("Only a service account", person.Message);
        Assert.Null((await lookup.GetAsync(admin.Id))!.Picture);
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

    [Fact]
    public async Task A_person_corrects_their_name_and_primary_address_and_the_old_one_hears_of_it()
    {
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);
        string id;
        using (JsonDocument me = JsonDocument.Parse(await admin.GetStringAsync("/api/guard/me")))
        {
            id = me.RootElement.GetProperty("account").GetProperty("id").GetString()!;
        }

        async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? body = null)
        {
            using HttpRequestMessage request = new(method, path) { Content = body is null ? null : JsonContent.Create(body) };
            request.Headers.Add(CsrfHeader, csrf);
            return await admin.SendAsync(request);
        }

        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Put, "/api/guard/me/name", new { displayName = "Ada Admin" })).StatusCode);
        await AssertErrorAsync(await SendAsync(HttpMethod.Put, "/api/guard/me/name", new { displayName = " " }), HttpStatusCode.BadRequest, null);
        using (JsonDocument me = JsonDocument.Parse(await admin.GetStringAsync("/api/guard/me")))
        {
            Assert.Equal("Ada Admin", me.RootElement.GetProperty("account").GetProperty("displayName").GetString());
        }

        // An admin's address is confirmed at once; the person makes it their primary, and the one before stays theirs.
        HttpResponseMessage added = await SendAsync(HttpMethod.Post, $"/api/guard/accounts/{id}/emails", new { email = "ada@home.example" });
        Assert.Equal(HttpStatusCode.OK, added.StatusCode);
        string? before;
        string emailId;
        using (JsonDocument addresses = JsonDocument.Parse(await added.Content.ReadAsStringAsync()))
        {
            Assert.True(addresses.RootElement.GetProperty("correctable").GetBoolean());
            before = addresses.RootElement.GetProperty("directoryEmail").GetString();
            emailId = addresses.RootElement.GetProperty("addresses").EnumerateArray()
                .First(a => a.GetProperty("email").GetString() == "ada@home.example").GetProperty("id").GetString()!;
        }

        HttpResponseMessage primary = await SendAsync(HttpMethod.Post, $"/api/guard/me/emails/{emailId}/primary");
        Assert.Equal(HttpStatusCode.OK, primary.StatusCode);
        using (JsonDocument now = JsonDocument.Parse(await primary.Content.ReadAsStringAsync()))
        {
            Assert.Equal("ada@home.example", now.RootElement.GetProperty("directoryEmail").GetString());
            if (before is not null)
            {
                Assert.Contains(now.RootElement.GetProperty("addresses").EnumerateArray(),
                    a => a.GetProperty("email").GetString() == before && a.GetProperty("source").GetString() == "former-primary");
                Assert.Contains(Directory.GetFiles(_mail, "*.eml").Select(File.ReadAllText), m => m.Contains(before, StringComparison.OrdinalIgnoreCase)
                    && m.Contains("now uses ada@home.example", StringComparison.Ordinal));
            }
        }

        // Sign-in still takes the username, and the security log has both corrections.
        await SignInAsync(Client(), "admin", AdminPassword);
        await using NpgsqlConnection connection = new($"{Server};Database={_database}");
        await connection.OpenAsync();
        await using NpgsqlCommand audit = new(
            "SELECT string_agg(\"Type\", ',' ORDER BY \"Time\") FROM guard.security_events WHERE \"Type\" IN ('account.renamed', 'account.address.primary')", connection);
        Assert.Equal("account.renamed,account.address.primary", await audit.ExecuteScalarAsync());
    }

    [Fact]
    public async Task A_person_asks_to_be_erased_a_hold_stops_it_and_once_released_they_become_a_pseudonym()
    {
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);

        async Task<HttpResponseMessage> SendAsync(HttpClient client, string token, HttpMethod method, string path, object? body = null)
        {
            using HttpRequestMessage request = new(method, path) { Content = body is null ? null : JsonContent.Create(body) };
            request.Headers.Add(CsrfHeader, token);
            return await client.SendAsync(request);
        }

        // An erased account's username is kept for it, so no one takes "former-person-1" before the erasure needs it.
        await AssertErrorAsync(await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/accounts",
            new { username = "former-person-1", displayName = "Squatter", password = "Squat-Pass-12345" }), HttpStatusCode.BadRequest, "reserved_name");

        HttpResponseMessage created = await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/accounts",
            new { username = "erin", displayName = "Erin Example", email = "erin@example.test", password = "Erin-Pass-12345" });
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        string id;
        using (JsonDocument account = JsonDocument.Parse(await created.Content.ReadAsStringAsync()))
        {
            id = account.RootElement.GetProperty("id").GetString()!;
        }

        // Erin asks, from the You page.
        HttpClient erin = Client();
        string erinCsrf = await SignInAsync(erin, "erin", "Erin-Pass-12345");
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(erin, erinCsrf, HttpMethod.Post, "/api/guard/me/erasure-request", new { reason = "I've left." })).StatusCode);
        using (JsonDocument mine = JsonDocument.Parse(await erin.GetStringAsync("/api/guard/me/erasure-request")))
        {
            Assert.Equal("requested", mine.RootElement.GetProperty("state").GetString());
        }

        // A legal hold stops the erasure, with its own code, until it's released.
        HttpResponseMessage held = await SendAsync(admin, csrf, HttpMethod.Post, "/api/guard/privacy/holds", new { accountId = id, reason = "A case about invoices" });
        Assert.Equal(HttpStatusCode.OK, held.StatusCode);
        string holdId;
        using (JsonDocument hold = JsonDocument.Parse(await held.Content.ReadAsStringAsync()))
        {
            holdId = hold.RootElement.GetProperty("id").GetString()!;
            Assert.True(hold.RootElement.GetProperty("active").GetBoolean());
        }

        using (JsonDocument preview = JsonDocument.Parse(await admin.GetStringAsync($"/api/guard/accounts/{id}/erasure/preview")))
        {
            Assert.Single(preview.RootElement.GetProperty("holds").EnumerateArray());
            Assert.Contains(preview.RootElement.GetProperty("stores").EnumerateArray(), s => s.GetString() == "guard.accounts");
        }

        await AssertErrorAsync(await SendAsync(admin, csrf, HttpMethod.Post, $"/api/guard/accounts/{id}/erasure"), HttpStatusCode.BadRequest, "legal_hold");
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, csrf, HttpMethod.Post, $"/api/guard/privacy/holds/{holdId}/release")).StatusCode);

        HttpResponseMessage erased = await SendAsync(admin, csrf, HttpMethod.Post, $"/api/guard/accounts/{id}/erasure");
        Assert.Equal(HttpStatusCode.OK, erased.StatusCode);
        int number;
        using (JsonDocument erasure = JsonDocument.Parse(await erased.Content.ReadAsStringAsync()))
        {
            Assert.Equal("done", erasure.RootElement.GetProperty("state").GetString());
            number = erasure.RootElement.GetProperty("number").GetInt32();
            Assert.Equal($"Former person {number}", erasure.RootElement.GetProperty("pseudonym").GetString());
            Assert.All(erasure.RootElement.GetProperty("stores").EnumerateObject().Where(s => s.Name.StartsWith("guard.", StringComparison.Ordinal)),
                s => Assert.Equal("done", s.Value.GetString()));
        }

        // Her sessions ended.
        Assert.Equal(HttpStatusCode.Unauthorized, (await erin.GetAsync("/api/guard/me")).StatusCode);

        await using NpgsqlConnection connection = new($"{Server};Database={_database}");
        await connection.OpenAsync();
        async Task<object?> ScalarAsync(string sql)
        {
            await using NpgsqlCommand command = new(sql, connection);
            command.Parameters.AddWithValue("id", Guid.Parse(id));
            return await command.ExecuteScalarAsync();
        }

        Assert.Equal($"former-person-{number}|Former person {number}||true",
            await ScalarAsync("SELECT \"Username\" || '|' || \"DisplayName\" || '|' || coalesce(\"Email\", '') || '|' || (\"ErasedAt\" IS NOT NULL) FROM guard.accounts WHERE \"Id\" = @id"));
        Assert.Equal(0L, await ScalarAsync("SELECT count(*) FROM guard.sessions WHERE \"AccountId\" = @id"));
        Assert.Equal(0L, await ScalarAsync("SELECT count(*) FROM guard.directory_users WHERE \"NormalizedUsername\" = 'erin'"));
        Assert.Equal(0L, await ScalarAsync("SELECT count(*) FROM guard.security_events WHERE \"Username\" ILIKE '%erin%' OR \"TargetName\" ILIKE '%erin%' OR \"Detail\" ILIKE '%erin%'"));
        Assert.True((long)(await ScalarAsync("SELECT count(*) FROM guard.security_events WHERE \"TargetId\" = @id OR \"AccountId\" = @id"))! > 0);
        Assert.Equal(true, await ScalarAsync("SELECT bool_and(\"Subject\" IS NULL) FROM guard.erasures WHERE \"AccountId\" = @id"));
        Assert.Equal(DBNull.Value, await ScalarAsync("SELECT \"Address\" FROM guard.legal_holds WHERE \"AccountId\" = @id"));

        // Her username finds nothing now (the log notes the try, as it would anyone's).
        HttpResponseMessage signIn = await Client().PostAsJsonAsync("/api/guard/session", new { username = "erin", password = "Erin-Pass-12345" });
        Assert.NotEqual(HttpStatusCode.OK, signIn.StatusCode);
    }

    [Fact]
    public async Task A_new_site_keeps_by_the_default_periods_and_a_sweep_removes_a_sign_up_never_confirmed()
    {
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);

        async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? body = null)
        {
            using HttpRequestMessage request = new(method, path) { Content = body is null ? null : JsonContent.Create(body) };
            request.Headers.Add(CsrfHeader, csrf);
            return await admin.SendAsync(request);
        }

        // A new site starts confirmed, with Guard's two rules at their defaults.
        using (JsonDocument retention = JsonDocument.Parse(await admin.GetStringAsync("/api/guard/privacy/retention")))
        {
            Assert.True(retention.RootElement.GetProperty("confirmedByDefault").GetBoolean());
            JsonElement signUps = retention.RootElement.GetProperty("rules").EnumerateArray().Single(r => r.GetProperty("key").GetString() == "guard.unconfirmed-sign-ups");
            Assert.Equal(7, signUps.GetProperty("days").GetInt32());
        }

        await AssertErrorAsync(await SendAsync(HttpMethod.Put, "/api/guard/privacy/retention", new { days = new Dictionary<string, int?> { ["guard.unconfirmed-sign-ups"] = 0 }, confirm = true }),
            HttpStatusCode.BadRequest, null);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Put, "/api/guard/privacy/retention",
            new { days = new Dictionary<string, int?> { ["guard.unconfirmed-sign-ups"] = 3 }, confirm = true })).StatusCode);

        // Someone signs up and never confirms; four days later a sweep removes their record and account.
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Put, "/api/guard/signup/settings",
            new { enabled = true, directoryId = "00000000-0000-0000-0000-00000000d001", emailDomains = Array.Empty<string>() })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await Client().PostAsJsonAsync("/api/guard/signup",
            new { email = "nadia@example.test", displayName = "Nadia", password = "Nadia-Pass-12345" })).StatusCode);
        await using NpgsqlConnection connection = new($"{Server};Database={_database}");
        await connection.OpenAsync();
        await using (NpgsqlCommand age = new("UPDATE guard.directory_users SET \"PendingSince\" = now() - interval '4 days' WHERE \"NormalizedUsername\" = 'NADIA@EXAMPLE.TEST' OR lower(\"Username\") = 'nadia@example.test'", connection))
        {
            Assert.Equal(1, await age.ExecuteNonQueryAsync());
        }

        HttpResponseMessage swept = await SendAsync(HttpMethod.Post, "/api/guard/privacy/retention/sweep");
        Assert.Equal(HttpStatusCode.OK, swept.StatusCode);
        using (JsonDocument counts = JsonDocument.Parse(await swept.Content.ReadAsStringAsync()))
        {
            Assert.Equal(1, counts.RootElement.GetProperty("guard.unconfirmed-sign-ups").GetInt32());
        }

        await using NpgsqlCommand left = new("SELECT count(*) FROM guard.directory_users WHERE lower(\"Username\") = 'nadia@example.test'", connection);
        Assert.Equal(0L, await left.ExecuteScalarAsync());
        await using NpgsqlCommand accounts = new("SELECT count(*) FROM guard.accounts WHERE lower(\"Username\") = 'nadia@example.test'", connection);
        Assert.Equal(0L, await accounts.ExecuteScalarAsync());
        await using NpgsqlCommand logged = new("SELECT count(*) FROM guard.security_events WHERE \"Type\" = 'privacy.retention.swept'", connection);
        Assert.Equal(1L, await logged.ExecuteScalarAsync());

        // An import's placeholder with the username a sign-up then takes and never confirms: the sweep removes the sign-up,
        // and the placeholder keeps its account, which the import's records name.
        Guid placeholder;
        using (IServiceScope scope = _factory!.Services.CreateScope())
        {
            placeholder = (await scope.ServiceProvider.GetRequiredService<IAccountProvisioning>()
                .MatchOrCreatePlaceholderAsync("Tracker", "pia@example.test", "Pia", "pia@example.test")).AccountId;
        }

        Assert.Equal(HttpStatusCode.NoContent, (await Client().PostAsJsonAsync("/api/guard/signup",
            new { email = "pia@example.test", displayName = "Pia", password = "Pia-Pass-123456" })).StatusCode);
        await using (NpgsqlCommand age = new("UPDATE guard.directory_users SET \"PendingSince\" = now() - interval '4 days' WHERE \"PendingSince\" IS NOT NULL", connection))
        {
            Assert.Equal(1, await age.ExecuteNonQueryAsync());
        }

        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Post, "/api/guard/privacy/retention/sweep")).StatusCode);
        await using NpgsqlCommand kept = new("SELECT count(*) FROM guard.accounts a JOIN guard.directory_users u ON u.\"Id\" = a.\"DirectoryUserId\" WHERE a.\"Id\" = @id AND u.\"PendingSince\" IS NULL", connection);
        kept.Parameters.AddWithValue("id", placeholder);
        Assert.Equal(1L, await kept.ExecuteScalarAsync());
    }

    [Fact]
    public async Task A_published_notice_is_accepted_on_sign_up_asked_again_when_it_changes_and_consent_is_withdrawn()
    {
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);

        async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? body = null)
        {
            using HttpRequestMessage request = new(method, path) { Content = body is null ? null : JsonContent.Create(body) };
            request.Headers.Add(CsrfHeader, csrf);
            return await admin.SendAsync(request);
        }

        // No notice yet: nothing to read or accept.
        Assert.Equal(HttpStatusCode.NoContent, (await Client().GetAsync("/api/guard/privacy-notice")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Post, "/api/guard/privacy/notices",
            new { texts = new Dictionary<string, object> { ["en"] = new { markdown = "# How we use your data" }, ["ar"] = new { link = "https://example.test/privacy-ar" } } })).StatusCode);
        using (JsonDocument notice = JsonDocument.Parse(await Client().GetStringAsync("/api/guard/privacy-notice?language=ar")))
        {
            Assert.Equal(1, notice.RootElement.GetProperty("version").GetInt32());
            Assert.Equal("https://example.test/privacy-ar", notice.RootElement.GetProperty("link").GetString());
        }

        // Sign-up shows it and must carry the version it showed.
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Put, "/api/guard/signup/settings",
            new { enabled = true, directoryId = "00000000-0000-0000-0000-00000000d001", emailDomains = Array.Empty<string>() })).StatusCode);
        await AssertErrorAsync(await Client().PostAsJsonAsync("/api/guard/signup", new { email = "lina@example.test", displayName = "Lina", password = "Lina-Pass-123456" }),
            HttpStatusCode.BadRequest, "accept_notice");
        Assert.Equal(HttpStatusCode.NoContent, (await Client().PostAsJsonAsync("/api/guard/signup",
            new { email = "lina@example.test", displayName = "Lina", password = "Lina-Pass-123456", noticeVersion = 1 })).StatusCode);

        // The admin, signed in, never accepted it; a new version asks again.
        using (JsonDocument mine = JsonDocument.Parse(await admin.GetStringAsync("/api/guard/me/privacy")))
        {
            Assert.True(mine.RootElement.GetProperty("needsAcceptance").GetBoolean());
        }

        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Post, "/api/guard/me/privacy/accept", new { version = 1 })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Post, "/api/guard/privacy/notices",
            new { texts = new Dictionary<string, object> { ["en"] = new { markdown = "# How we use your data, now" } } })).StatusCode);
        using (JsonDocument mine = JsonDocument.Parse(await admin.GetStringAsync("/api/guard/me/privacy")))
        {
            Assert.True(mine.RootElement.GetProperty("needsAcceptance").GetBoolean());
            Assert.Equal(1, mine.RootElement.GetProperty("acceptedVersion").GetInt32());
        }

        await AssertErrorAsync(await SendAsync(HttpMethod.Post, "/api/guard/me/privacy/accept", new { version = 1 }), HttpStatusCode.BadRequest, "accept_notice");
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Post, "/api/guard/me/privacy/accept", new { version = 2 })).StatusCode);

        // Where a store's basis is consent, a person withdraws theirs and an admin marks it handled.
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Put, "/api/guard/privacy/stores/guard.sessions", new { legalBasis = "consent" })).StatusCode);
        HttpResponseMessage withdrawn = await SendAsync(HttpMethod.Post, "/api/guard/me/privacy/withdraw", new { store = "guard.sessions" });
        Assert.Equal(HttpStatusCode.OK, withdrawn.StatusCode);
        await AssertErrorAsync(await SendAsync(HttpMethod.Post, "/api/guard/me/privacy/withdraw", new { store = "guard.accounts" }), HttpStatusCode.BadRequest, null);
        string withdrawalId;
        using (JsonDocument list = JsonDocument.Parse(await admin.GetStringAsync("/api/guard/privacy/consent-withdrawals")))
        {
            JsonElement first = Assert.Single(list.RootElement.EnumerateArray());
            Assert.Equal("guard.sessions", first.GetProperty("store").GetString());
            withdrawalId = first.GetProperty("id").GetString()!;
        }

        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Post, $"/api/guard/privacy/consent-withdrawals/{withdrawalId}/handled", new { note = "Signed out everywhere" })).StatusCode);
        string record = await admin.GetStringAsync("/api/guard/privacy/record?language=en");
        Assert.Contains("Version 2", record, StringComparison.Ordinal);

        await using NpgsqlConnection connection = new($"{Server};Database={_database}");
        await connection.OpenAsync();
        await using NpgsqlCommand accepted = new("SELECT string_agg(\"Where\" || ':' || \"Version\", ',' ORDER BY \"At\") FROM guard.privacy_acceptances", connection);
        Assert.Equal("sign-up:1,sign-in:1,sign-in:2", await accepted.ExecuteScalarAsync());
    }

    [Fact]
    public async Task Apps_may_not_register_themselves_on_a_new_site_until_an_admin_lets_them()
    {
        // The sample host has no registration endpoint at all (GuardFeatures.ClientRegistration off); a new site's setting is off too.
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);
        using (JsonDocument settings = JsonDocument.Parse(await admin.GetStringAsync("/api/guard/security/settings")))
        {
            Assert.False(settings.RootElement.GetProperty("appsMayRegister").GetBoolean());
        }

        Assert.Contains("Off: only apps a site admin adds", await admin.GetStringAsync("/api/guard/privacy/record?language=en"), StringComparison.Ordinal);
        using HttpRequestMessage turnOn = new(HttpMethod.Put, "/api/guard/security/settings")
        {
            Content = JsonContent.Create(new { retentionDays = 730, stepUpMinutes = 10, appsMayRegister = true }),
        };
        turnOn.Headers.Add(CsrfHeader, csrf);
        HttpResponseMessage saved = await admin.SendAsync(turnOn);
        Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
        using (JsonDocument settings = JsonDocument.Parse(await saved.Content.ReadAsStringAsync()))
        {
            Assert.True(settings.RootElement.GetProperty("appsMayRegister").GetBoolean());
        }

        Assert.Contains("On: an app may register itself", await admin.GetStringAsync("/api/guard/privacy/record?language=en"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_burst_of_failed_sign_ins_alerts_the_admins_and_the_log_downloads_and_feeds_safely()
    {
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);

        async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? body = null)
        {
            using HttpRequestMessage request = new(method, path) { Content = body is null ? null : JsonContent.Create(body) };
            request.Headers.Add(CsrfHeader, csrf);
            return await admin.SendAsync(request);
        }

        // A burst of failed sign-ins (the limiter blocks most of them): the next check tells the site admins, once. It's the
        // site's first check, which looks back a window: what happened before it is told too.
        using (IServiceScope scope = _factory!.Services.CreateScope())
        {
            AbpGuard.Services.SecurityAlerts alerts = scope.ServiceProvider.GetRequiredService<AbpGuard.Services.SecurityAlerts>();
            for (int i = 0; i < 25; i++)
            {
                await Client().PostAsJsonAsync("/api/guard/session", new { username = $"=cmd|' /C calc'!A{i}", password = "wrong" });
            }

            List<AbpGuard.Services.SecurityAlert> told = await alerts.CheckAsync(CancellationToken.None);
            Assert.Contains(told, a => a.Kind is "failed-sign-ins" or "auth.login.blocked");
            Assert.DoesNotContain(await alerts.CheckAsync(CancellationToken.None), a => told.Any(t => t.Kind == a.Kind));
        }

        Assert.Contains(Directory.GetFiles(_mail, "*.eml").Select(File.ReadAllText), m => m.Contains("Security alert:", StringComparison.Ordinal));

        // The log downloads as CSV, a formula someone typed as a username kept as text, and the download is logged.
        HttpResponseMessage csv = await admin.GetAsync("/api/guard/security-events/export?type=auth.login.failed");
        Assert.Equal(HttpStatusCode.OK, csv.StatusCode);
        string text = await csv.Content.ReadAsStringAsync();
        Assert.Contains("'=cmd|", text, StringComparison.Ordinal);
        Assert.DoesNotContain(",=cmd|", text, StringComparison.Ordinal);
        using (JsonDocument logged = JsonDocument.Parse(await admin.GetStringAsync("/api/guard/security-events?type=security.log.exported")))
        {
            Assert.Equal(1, logged.RootElement.GetProperty("total").GetInt32());
        }

        // The feed: https only, a secret before it's on, shown once.
        await AssertErrorAsync(await SendAsync(HttpMethod.Put, "/api/guard/security/feed", new { url = "http://siem.example.test/in", enabled = false }), HttpStatusCode.BadRequest, null);
        await AssertErrorAsync(await SendAsync(HttpMethod.Put, "/api/guard/security/feed", new { url = "https://siem.example.test/in", enabled = true }), HttpStatusCode.BadRequest, "no_secret");
        using (JsonDocument secret = JsonDocument.Parse(await (await SendAsync(HttpMethod.Post, "/api/guard/security/feed/secret")).Content.ReadAsStringAsync()))
        {
            Assert.Equal(44, secret.RootElement.GetProperty("secret").GetString()!.Length);
        }

        HttpResponseMessage on = await SendAsync(HttpMethod.Put, "/api/guard/security/feed", new { url = "https://siem.example.test/in", enabled = true });
        Assert.Equal(HttpStatusCode.OK, on.StatusCode);
        using (JsonDocument feed = JsonDocument.Parse(await on.Content.ReadAsStringAsync()))
        {
            Assert.True(feed.RootElement.GetProperty("hasSecret").GetBoolean());
            Assert.False(feed.RootElement.TryGetProperty("secret", out _));
        }
    }

    [Fact]
    public async Task A_hosts_plugin_rename_moves_what_Guard_keeps_by_plugin_once_and_a_row_already_under_the_new_key_wins()
    {
        _ = Client();
        using IServiceScope scope = _factory!.Services.CreateScope();
        Services.GuardDb guardDb = scope.ServiceProvider.GetRequiredService<Services.GuardDb>();
        Guid person = Guid.NewGuid();
        Guid running = Guid.NewGuid(), done = Guid.NewGuid();
        await guardDb.RunAsync(async db =>
        {
            db.PrivacyStores.AddRange(
                new Domain.PrivacyStoreRecord("guard-ldap.entries") { LegalBasis = Domain.LegalBases.Agreement, Notes = "kept" },
                new Domain.PrivacyStoreRecord("seeder.people") { Notes = "former" },
                new Domain.PrivacyStoreRecord("acme.seeder.people") { Notes = "new" },
                new Domain.PrivacyStoreRecord("guard-ldap.x.entries"),
                new Domain.PrivacyStoreRecord("guard.accounts"));
            db.ConsentWithdrawals.Add(new Domain.ConsentWithdrawal(Guid.NewGuid(), person, "guard-ldap.entries"));
            db.RetentionPeriods.AddRange(new Domain.RetentionPeriod { RuleKey = "guard-ldap.logs", Days = 30, LastCount = 4 },
                new Domain.RetentionPeriod { RuleKey = "guard.sessions", Days = 90 });
            Domain.SecuritySettings settings = await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.FirstOrDefaultAsync(db.SecuritySettings)
                ?? db.SecuritySettings.Add(new Domain.SecuritySettings(Domain.SecuritySettings.SingletonId)).Entity;
            settings.SecondFactorMethods = ["email", "messaging:sms", "messaging:whatsapp", "acme.messaging:whatsapp"];
            db.Erasures.AddRange(
                new Domain.PersonalDataErasureRecord(running, null, "{}", Domain.ErasureStates.Running) { Stores = """{"guard-ldap.entries":"failed","guard.accounts":"done"}""" },
                new Domain.PersonalDataErasureRecord(done, null, null, Domain.ErasureStates.Done) { Stores = """{"guard-ldap.entries":"done"}""" });
            await db.SaveChangesAsync();
        }, requiresNew: true);

        Services.Privacy.PersonalDataKeys keys = scope.ServiceProvider.GetRequiredService<Services.Privacy.PersonalDataKeys>();
        Dictionary<string, string> former = new() { ["guard-ldap"] = "acme.ldap", ["seeder"] = "acme.seeder", ["messaging"] = "acme.messaging" };
        Assert.Equal(new Services.Privacy.PluginRenameCounts(1, 1, 1, 1, 1), await keys.RenamePluginsAsync(former));

        await guardDb.RunAsync(async db =>
        {
            Dictionary<string, Domain.PrivacyStoreRecord> stores = await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.ToDictionaryAsync(db.PrivacyStores, s => s.StoreKey);
            Assert.Equal(["acme.ldap.entries", "acme.seeder.people", "guard-ldap.x.entries", "guard.accounts", "seeder.people"], stores.Keys.Order(StringComparer.Ordinal));
            Assert.Equal((Domain.LegalBases.Agreement, "kept"), (stores["acme.ldap.entries"].LegalBasis, stores["acme.ldap.entries"].Notes));
            Assert.Equal("new", stores["acme.seeder.people"].Notes);
            Assert.Equal("acme.ldap.entries", db.ConsentWithdrawals.Single(w => w.AccountId == person).StoreKey);
            Assert.Equal(["acme.ldap.logs", "guard.sessions"], db.RetentionPeriods.Select(p => p.RuleKey).AsEnumerable().Order(StringComparer.Ordinal));
            Assert.Equal((30, 4), db.RetentionPeriods.Where(p => p.RuleKey == "acme.ldap.logs").Select(p => new ValueTuple<int?, int>(p.Days, p.LastCount)).Single());
            Assert.Equal(["email", "acme.messaging:sms", "messaging:whatsapp", "acme.messaging:whatsapp"], db.SecuritySettings.Single().SecondFactorMethods);
            Dictionary<Guid, string> erasures = db.Erasures.ToDictionary(e => e.Id, e => e.Stores);
            Assert.Equal(new Dictionary<string, string> { ["acme.ldap.entries"] = "failed", ["guard.accounts"] = "done" },
                JsonSerializer.Deserialize<Dictionary<string, string>>(erasures[running]));
            Assert.Equal(new Dictionary<string, string> { ["guard-ldap.entries"] = "done" }, JsonSerializer.Deserialize<Dictionary<string, string>>(erasures[done]));
        });

        // A second start moves nothing.
        Assert.Equal(0, (await keys.RenamePluginsAsync(former)).Total);
    }

    [Theory]
    [InlineData("guard-ldap.entries", '.', "acme.ldap.entries")]
    [InlineData("messaging:sms", ':', "acme.messaging:sms")]
    [InlineData("guard-ldap.x.entries", '.', null)]
    [InlineData("guard-ldapx.entries", '.', null)]
    [InlineData("guard-ldap.", '.', null)]
    [InlineData("acme.ldap.entries", '.', null)]
    public void A_key_is_the_former_plugins_only_with_its_separator_and_one_name(string key, char separator, string? renamed) =>
        Assert.Equal(renamed, Services.Privacy.PersonalDataKeys.Renamed(key, "guard-ldap", "acme.ldap", separator)
            ?? Services.Privacy.PersonalDataKeys.Renamed(key, "messaging", "acme.messaging", separator));

    private static async Task AssertErrorAsync(HttpResponseMessage response, HttpStatusCode status, string? code)
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
