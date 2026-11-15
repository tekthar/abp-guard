using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using AbpGuard.Acting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Volo.Abp;
using Volo.Abp.Autofac;
using Volo.Abp.Data;
using Volo.Abp.Domain.Entities;
using Volo.Abp.EntityFrameworkCore;
using Volo.Abp.EntityFrameworkCore.PostgreSql;
using Volo.Abp.Modularity;
using Volo.Abp.Uow;

namespace AbpConnections.Tests;

/// <summary>
/// Connections in an application's own database, against a fake OAuth provider: a secret is kept encrypted and never
/// shown, a blank one keeps the stored one, sign-in is the authorization code with PKCE and a state only its starter can
/// finish, an expired token is refreshed once for every caller waiting, a refused refresh ends the sign-in, each person
/// signs in with their own account, a connection in use isn't removed, and the audit hears every change without a
/// secret. Needs PostgreSQL: localhost:5432 (postgres/postgres), or the server GUARD_TEST_POSTGRES names.
/// </summary>
public class ManagerTests
{
    private static readonly Guid Admin = Guid.NewGuid();

    [Fact]
    public async Task A_secret_is_kept_encrypted_and_a_blank_one_keeps_it()
    {
        await using ConnectionsApp app = await ConnectionsApp.StartAsync();
        ConnectionView made = await app.Manager.CreateAsync(new("Reports", "api-key", new() { ["url"] = " https://api.example.com " }, new() { ["key"] = "k-123" }), null, Admin, default);
        Assert.Equal((ConnectionStatus.Ready, "https://api.example.com", true), (made.Status, made.Settings["url"], made.Secrets["key"]));

        Connection row = await app.RowAsync(made.Id);
        Assert.DoesNotContain("k-123", row.ProtectedSecrets);
        ConnectionView kept = await app.Manager.UpdateAsync(made.Id, new("Reports 2", "api-key", new() { ["url"] = "https://api.example.com" }, new() { ["key"] = "" }), null, default);
        Assert.Equal(("Reports 2", true), (kept.Name, kept.Secrets["key"]));
        Assert.Equal("k-123", (await app.Manager.GetForUseAsync(made.Id, default))!.Secrets["key"]);

        UserFriendlyException missing = await Assert.ThrowsAsync<UserFriendlyException>(() =>
            app.Manager.CreateAsync(new("No key", "api-key", new() { ["url"] = "https://x" }, null), null, Admin, default));
        Assert.Equal("'API key' is required.", missing.Message);
        Assert.Equal([ConnectionAuditTypes.Created, ConnectionAuditTypes.Updated], app.Audit.Entries.Select(e => e.Type));
        Assert.DoesNotContain("k-123", string.Join(" ", app.Audit.Entries.Select(e => JsonSerializer.Serialize(e.Detail))));
    }

    [Fact]
    public async Task Sign_in_is_the_code_with_pkce_and_only_its_starter_finishes_it()
    {
        await using ConnectionsApp app = await ConnectionsApp.StartAsync();
        ConnectionView made = await app.Manager.CreateAsync(new("Drive", "oauth", null, null), null, Admin, default);
        Assert.Equal(ConnectionStatus.NeedsSignIn, made.Status);

        string url = await app.Manager.AuthorizeAsync(made.Id, null, "https://app.test/connections/callback", Admin, default);
        Dictionary<string, string> query = Query(url);
        Assert.StartsWith("https://provider.test/common/authorize?", url);
        Assert.Equal(("code", "client-1", "S256", "files"), (query["response_type"], query["client_id"], query["code_challenge_method"], query["scope"]));
        await Assert.ThrowsAsync<UserFriendlyException>(() => app.Manager.AuthorizeAsync(made.Id, null, "https://app.test/elsewhere", Admin, default));

        await Assert.ThrowsAsync<UserFriendlyException>(() => app.Manager.CompleteAsync("code-1", query["state"], Guid.NewGuid(), default)); // someone else
        ConnectionView signedIn = await app.Manager.CompleteAsync("code-1", query["state"], Admin, default);
        Assert.Equal((ConnectionStatus.Ready, true, "dana@example.com"), (signedIn.Status, signedIn.SignedIn, signedIn.Account));
        Received token = app.Provider.Requests.First(r => r.Form["grant_type"] == "authorization_code");
        Assert.Equal(query["code_challenge"], Challenge(token.Form["code_verifier"]));
        Assert.Equal("access-1", (await app.Manager.GetForUseAsync(made.Id, default))!.AccessToken);
        Assert.Contains(app.Audit.Entries, e => e.Type == ConnectionAuditTypes.SignedIn);
    }

    [Fact]
    public async Task An_expired_token_is_refreshed_once_for_every_caller_and_a_refusal_ends_the_sign_in()
    {
        await using ConnectionsApp app = await ConnectionsApp.StartAsync();
        Guid id = await app.SignedInAsync();
        await app.ExpireAsync(id);

        ConnectionInUse?[] used = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => app.NewManager().GetForUseAsync(id, default)));
        Assert.All(used, u => Assert.Equal("access-2", u!.AccessToken));
        Assert.Single(app.Provider.Requests, r => r.Form["grant_type"] == "refresh_token");

        await app.ExpireAsync(id);
        app.Provider.RefuseRefresh = true;
        UserFriendlyException refused = await Assert.ThrowsAsync<UserFriendlyException>(() => app.Manager.GetForUseAsync(id, default));
        Assert.StartsWith("Drive must sign in again: The provider refused:", refused.Message);
        Assert.Equal((ConnectionStatus.NeedsSignIn, null), ((await app.RowAsync(id)).Status, (await app.RowAsync(id)).ProtectedTokens));
    }

    [Fact]
    public async Task Each_person_signs_in_with_their_own_account()
    {
        await using ConnectionsApp app = await ConnectionsApp.StartAsync();
        ConnectionView made = await app.Manager.CreateAsync(new("Mail", "oauth", null, null, EachPerson: true), null, Admin, default);
        Assert.Equal(ConnectionStatus.Ready, made.Status);
        Guid dana = Guid.NewGuid();

        PersonNotSignedInException notYet = await Assert.ThrowsAsync<PersonNotSignedInException>(() => app.Manager.ForPersonAsync(made.Id, dana, default));
        Assert.Equal("You haven't signed in to Mail: sign in from the connected accounts page, then ask again.", notYet.Message);
        await Assert.ThrowsAsync<UserFriendlyException>(() => app.Manager.AuthorizeAsync(made.Id, null, "https://app.test/connections/callback", dana, default)); // not personal

        string url = await app.Manager.AuthorizeAsync(made.Id, null, "https://app.test/connections/callback", dana, default, personal: true);
        await app.Manager.CompleteAsync("code-1", Query(url)["state"], dana, default);
        Assert.Equal("access-1", (await app.Manager.ForPersonAsync(made.Id, dana, default)).AccessToken);
        Assert.Equal((true, "dana@example.com"), ((await app.Manager.PersonalListAsync(dana, [], default)).Single().SignedIn, (await app.Manager.PersonalListAsync(dana, [], default)).Single().Account));
        Assert.Null((await app.RowAsync(made.Id)).ProtectedTokens); // the connection itself holds no one's tokens
        Assert.Equal(1, (await app.Manager.GetAsync(made.Id, null, default)).PeopleSignedIn);

        await app.Manager.SignOutPersonAsync(made.Id, dana, default);
        Assert.False((await app.Manager.PersonalListAsync(dana, [], default)).Single().SignedIn);
    }

    [Fact]
    public async Task A_connection_in_use_is_not_removed_and_scopes_keep_apart()
    {
        await using ConnectionsApp app = await ConnectionsApp.StartAsync();
        Guid scope = Guid.NewGuid();
        ConnectionView site = await app.Manager.CreateAsync(new("Site key", "api-key", new() { ["url"] = "https://x" }, new() { ["key"] = "k" }), null, Admin, default);
        ConnectionView scoped = await app.Manager.CreateAsync(new("Scope key", "api-key", new() { ["url"] = "https://x" }, new() { ["key"] = "k" }), scope, Admin, default);

        Assert.Equal(["Site key"], (await app.Manager.ListAsync(null, default)).Select(c => c.Name));
        Assert.Equal(["Scope key"], (await app.Manager.ListAsync(scope, default)).Select(c => c.Name));
        await Assert.ThrowsAsync<EntityNotFoundException>(() => app.Manager.GetAsync(scoped.Id, null, default));
        Assert.Equal(["Scope key", "Site key"], (await app.Manager.ListOfTypeAsync("api-key", scope, default)).Select(c => c.Name).Order());

        app.Uses.Using[site.Id] = "the reports job";
        UserFriendlyException inUse = await Assert.ThrowsAsync<UserFriendlyException>(() => app.Manager.DeleteAsync(site.Id, null, default));
        Assert.Equal("Site key is in use: the reports job. Stop using it first.", inUse.Message);
        app.Uses.Using.Clear();
        await app.Manager.DeleteAsync(site.Id, null, default);
        Assert.Empty(await app.Manager.ListAsync(null, default));
    }

    [Fact]
    public async Task A_settings_change_asks_a_step_up_when_the_connection_holds_a_secret_or_a_sign_in()
    {
        await using ConnectionsApp app = await ConnectionsApp.StartAsync();
        ConnectionView key = await app.Manager.CreateAsync(new("Reports", "api-key", new() { ["url"] = "https://api.example.com" }, new() { ["key"] = "k-123" }), null, Admin, default);
        // A new address would send the stored key there on the next test.
        Assert.True(await app.Manager.ChangeNeedsStepUpAsync(key.Id, null, new("Reports", "api-key", new() { ["url"] = "https://elsewhere.example" }, null), default));
        Assert.True(await app.Manager.ChangeNeedsStepUpAsync(key.Id, null, new("Reports", "api-key", new() { ["url"] = "https://api.example.com" }, new() { ["key"] = "k-456" }), default));
        Assert.False(await app.Manager.ChangeNeedsStepUpAsync(key.Id, null, new("Renamed", "api-key", new() { ["url"] = " https://api.example.com " }, new() { ["key"] = "" }), default));

        ConnectionView drive = await app.Manager.CreateAsync(new("Drive", "oauth", null, null), null, Admin, default);
        ConnectionChange folder = new("Drive", "oauth", new() { ["folder"] = "/reports" }, null);
        Assert.False(await app.Manager.ChangeNeedsStepUpAsync(drive.Id, null, folder, default)); // it holds nothing yet
        Guid signedIn = await app.SignedInAsync();
        Assert.True(await app.Manager.ChangeNeedsStepUpAsync(signedIn, null, folder, default));
        Assert.False(await app.Manager.ChangeNeedsStepUpAsync(signedIn, null, new("Drive 2", "oauth", new() { ["tenant"] = "common" }, null), default)); // the default, as kept

        await Assert.ThrowsAsync<EntityNotFoundException>(() => app.Manager.ChangeNeedsStepUpAsync(key.Id, Guid.NewGuid(), folder, default));
    }

    [Fact]
    public async Task Signing_in_somewhere_else_ends_every_sign_in_and_another_setting_keeps_them()
    {
        await using ConnectionsApp app = await ConnectionsApp.StartAsync();
        Guid id = await app.SignedInAsync();
        ConnectionView kept = await app.Manager.UpdateAsync(id, new("Drive", "oauth", new() { ["folder"] = "/reports" }, null), null, default);
        Assert.Equal((true, ConnectionStatus.Ready), (kept.SignedIn, kept.Status));

        ConnectionView moved = await app.Manager.UpdateAsync(id, new("Drive", "oauth", new() { ["tenant"] = "elsewhere", ["folder"] = "/reports" }, null), null, default);
        Assert.Equal((false, ConnectionStatus.NeedsSignIn, null), (moved.SignedIn, moved.Status, moved.Account));
        Assert.Null((await app.Manager.GetForUseAsync(id, default))!.AccessToken);
        Assert.DoesNotContain(app.Provider.Requests, r => r.Url.Contains("/elsewhere/"));
        Assert.Contains("\"signedOut\":true", JsonSerializer.Serialize(app.Audit.Entries.Last(e => e.Type == ConnectionAuditTypes.Updated).Detail));

        // Each person's own sign-ins end too, and the connection stays ready for them to sign in again.
        ConnectionView mail = await app.Manager.CreateAsync(new("Mail", "oauth", null, null, EachPerson: true), null, Admin, default);
        Guid dana = Guid.NewGuid();
        string url = await app.Manager.AuthorizeAsync(mail.Id, null, "https://app.test/connections/callback", dana, default, personal: true);
        await app.Manager.CompleteAsync("code-1", Query(url)["state"], dana, default);
        ConnectionView mailMoved = await app.Manager.UpdateAsync(mail.Id, new("Mail", "oauth", new() { ["tenant"] = "elsewhere" }, null), null, default);
        Assert.Equal((ConnectionStatus.Ready, 0), (mailMoved.Status, mailMoved.PeopleSignedIn));
        Assert.False((await app.Manager.PersonalListAsync(dana, [], default)).Single().SignedIn);
    }

    private static Dictionary<string, string> Query(string url) =>
        new Uri(url).Query.TrimStart('?').Split('&').Select(p => p.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]));

    private static string Challenge(string verifier) =>
        Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>A kind that signs in with OAuth at the fake provider: the tenant says where, the folder is only its own.</summary>
public sealed class OAuthKind : IConnectionKind
{
    public string Type => "oauth";
    public string DisplayName => "Drive";
    public IReadOnlyList<ConnectionSetting> Settings => [new("tenant", "Tenant", DefaultValue: "common"), new("folder", "Folder")];
    public bool SignsIn => true;

    public ConnectionOAuthSetup? OAuth(IReadOnlyDictionary<string, string> settings, IReadOnlyDictionary<string, string> secrets) =>
        new($"https://provider.test/{settings["tenant"]}/authorize", $"https://provider.test/{settings["tenant"]}/token", ["files"], "client-1", "secret-1");

    public Task<ConnectionTestResult> TestAsync(ConnectionInUse connection, HttpClient http, CancellationToken cancellationToken) =>
        Task.FromResult(new ConnectionTestResult(connection.AccessToken is not null, connection.AccessToken is null ? "No token." : "It answered.", "dana@example.com"));
}

/// <summary>A kind with an address and a key.</summary>
public sealed class KeyKind : IConnectionKind
{
    public string Type => "api-key";
    public string DisplayName => "API key";
    public IReadOnlyList<ConnectionSetting> Settings => [new("url", "Address", Required: true), new("key", "API key", Secret: true, Required: true)];
    public bool SignsIn => false;
    public ConnectionOAuthSetup? OAuth(IReadOnlyDictionary<string, string> settings, IReadOnlyDictionary<string, string> secrets) => null;

    public Task<ConnectionTestResult> TestAsync(ConnectionInUse connection, HttpClient http, CancellationToken cancellationToken) =>
        Task.FromResult(new ConnectionTestResult(true, "It answered."));
}

public sealed record Received(string Url, Dictionary<string, string> Form);

/// <summary>The fake provider's token endpoint: a code or a refresh token for tokens, slowly, so callers queue.</summary>
public sealed class Provider
{
    private int _issued;

    public ConcurrentQueue<Received> Log { get; } = new();

    public IReadOnlyList<Received> Requests => [.. Log];

    public bool RefuseRefresh { get; set; }

    internal async Task<HttpResponseMessage> AnswerAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string body = await request.Content!.ReadAsStringAsync(cancellationToken);
        Dictionary<string, string> form = body.Split('&').Select(p => p.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1].Replace('+', ' ')));
        Log.Enqueue(new Received(request.RequestUri!.ToString(), form));
        await Task.Delay(100, cancellationToken);
        if (form["grant_type"] == "refresh_token" && RefuseRefresh)
        {
            return new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent("{\"error\":\"invalid_grant\"}") };
        }

        int n = Interlocked.Increment(ref _issued);
        string idToken = "h." + Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"email\":\"dana@example.com\"}")).TrimEnd('=') + ".s";
        string json = JsonSerializer.Serialize(new Dictionary<string, object> { ["access_token"] = $"access-{n}", ["refresh_token"] = $"refresh-{n}", ["expires_in"] = 3600, ["id_token"] = idToken });
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    }
}

internal sealed class ProviderHandler(Provider provider) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => provider.AnswerAsync(request, cancellationToken);
}

public sealed record AuditEntry(string Type, AuditTarget? Target, object? Detail);

public sealed class Audit : ISecurityAudit
{
    public ConcurrentQueue<AuditEntry> Log { get; } = new();

    public IReadOnlyList<AuditEntry> Entries => [.. Log];

    public Task WriteAsync(string type, AuditTarget? target, object? detail, CancellationToken cancellationToken = default)
    {
        Log.Enqueue(new AuditEntry(type, target, detail));
        return Task.CompletedTask;
    }
}

public sealed class Uses : IConnectionUses
{
    public ConcurrentDictionary<Guid, string> Using { get; } = new();

    public Task<IReadOnlyList<string>> UsesAsync(Guid connectionId, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<string>>(Using.TryGetValue(connectionId, out string? what) ? [what] : []);
}

[ConnectionStringName("Default")]
public sealed class HostDb(DbContextOptions<HostDb> options) : AbpDbContext<HostDb>(options), IConnectionsDbContext
{
    public DbSet<Connection> Connections => Set<Connection>();

    public DbSet<ConnectionAccount> ConnectionAccounts => Set<ConnectionAccount>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ConfigureConnections("outside");
    }
}

[DependsOn(typeof(AbpConnectionsModule), typeof(AbpEntityFrameworkCorePostgreSqlModule), typeof(AbpAutofacModule))]
public sealed class ConnectionsHost : AbpModule
{
    public override void ConfigureServices(ServiceConfigurationContext context)
    {
        context.Services.AddAbpDbContext<HostDb>(options => options.ReplaceDbContext<IConnectionsDbContext>());
        Configure<AbpDbContextOptions>(options => options.UseNpgsql());
        context.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
        context.Services.AddSingleton<IConnectionKind, OAuthKind>();
        context.Services.AddSingleton<IConnectionKind, KeyKind>();
        context.Services.AddSingleton<Provider>();
        context.Services.AddSingleton<Audit>();
        context.Services.AddSingleton<ISecurityAudit>(sp => sp.GetRequiredService<Audit>());
        context.Services.AddSingleton<Uses>();
        context.Services.AddSingleton<IConnectionUses>(sp => sp.GetRequiredService<Uses>());
        context.Services.AddHttpClient("Connections").ConfigurePrimaryHttpMessageHandler(sp => new ProviderHandler(sp.GetRequiredService<Provider>()));
    }
}

/// <summary>The application on a database of its own, dropped after.</summary>
public sealed class ConnectionsApp : IAsyncDisposable
{
    private static readonly string Server =
        Environment.GetEnvironmentVariable("GUARD_TEST_POSTGRES") is { Length: > 0 } server ? server : "Host=localhost;Port=5432;Username=postgres;Password=postgres";

    private readonly IAbpApplicationWithInternalServiceProvider _app;

    private ConnectionsApp(IAbpApplicationWithInternalServiceProvider app) => _app = app;

    private IServiceProvider Services => _app.ServiceProvider;

    public ConnectionManager Manager => Services.GetRequiredService<ConnectionManager>();

    public ConnectionManager NewManager() => Services.CreateScope().ServiceProvider.GetRequiredService<ConnectionManager>();

    public Provider Provider => Services.GetRequiredService<Provider>();

    public Audit Audit => Services.GetRequiredService<Audit>();

    public Uses Uses => Services.GetRequiredService<Uses>();

    public static async Task<ConnectionsApp> StartAsync()
    {
        string database = "abp_connections_" + Guid.NewGuid().ToString("N")[..12];
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:Default"] = $"{Server};Database={database}" }).Build();
        IAbpApplicationWithInternalServiceProvider app = await AbpApplicationFactory.CreateAsync<ConnectionsHost>(o =>
        {
            o.UseAutofac();
            o.Services.ReplaceConfiguration(configuration);
        });
        await app.InitializeAsync();
        ConnectionsApp connections = new(app);
        await connections.RunAsync(async db => await db.Database.EnsureCreatedAsync());
        return connections;
    }

    /// <summary>A connection signed in for everyone.</summary>
    public async Task<Guid> SignedInAsync()
    {
        Guid admin = Guid.NewGuid();
        ConnectionView made = await Manager.CreateAsync(new("Drive", "oauth", null, null), null, admin, default);
        string url = await Manager.AuthorizeAsync(made.Id, null, "https://app.test/connections/callback", admin, default);
        string state = new Uri(url).Query.TrimStart('?').Split('&').Select(p => p.Split('=', 2)).First(p => p[0] == "state")[1];
        await Manager.CompleteAsync("code-1", Uri.UnescapeDataString(state), admin, default);
        return made.Id;
    }

    /// <summary>Makes the connection's token expire now, as stored.</summary>
    public Task ExpireAsync(Guid id) => RunAsync(async db =>
    {
        IDataProtector protector = Services.GetRequiredService<IDataProtectionProvider>().CreateProtector(new ConnectionsOptions().SecretsPurpose);
        Connection row = await db.Connections.FirstAsync(c => c.Id == id);
        Dictionary<string, object?> tokens = JsonSerializer.Deserialize<Dictionary<string, object?>>(protector.Unprotect(row.ProtectedTokens!))!;
        tokens["expiresAt"] = DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds();
        row.ProtectedTokens = protector.Protect(JsonSerializer.Serialize(tokens));
        return await db.SaveChangesAsync();
    });

    public Task<Connection> RowAsync(Guid id) => RunAsync(db => db.Connections.AsNoTracking().FirstAsync(c => c.Id == id));

    private async Task<T> RunAsync<T>(Func<HostDb, Task<T>> work)
    {
        using IServiceScope scope = Services.CreateScope();
        using IUnitOfWork uow = scope.ServiceProvider.GetRequiredService<IUnitOfWorkManager>().Begin(requiresNew: true);
        HostDb db = (HostDb)await scope.ServiceProvider.GetRequiredService<IDbContextProvider<IConnectionsDbContext>>().GetDbContextAsync();
        T result = await work(db);
        await uow.CompleteAsync();
        return result;
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await RunAsync(async db => await db.Database.EnsureDeletedAsync());
        }
        finally
        {
            await _app.ShutdownAsync();
            _app.Dispose();
        }
    }
}
