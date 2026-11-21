using System.Collections.Concurrent;
using System.Text;
using AbpConnections;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Volo.Abp;
using Volo.Abp.Autofac;
using Volo.Abp.Data;
using Volo.Abp.EntityFrameworkCore;
using Volo.Abp.EntityFrameworkCore.PostgreSql;
using Volo.Abp.Modularity;

namespace AbpNotify.Tests;

/// <summary>
/// The application on a database of its own, dropped after: its tables in a schema of its own, under the column names
/// an older table kept (<c>ProjectId</c>, <c>RecordId</c>, <c>RecordKey</c>), so the raw SQL is seen to take its names
/// from the model. Needs PostgreSQL: localhost:5432 (postgres/postgres), or the server GUARD_TEST_POSTGRES names.
/// </summary>
public sealed class NotifyApp : IAsyncDisposable
{
    private static readonly string Server =
        Environment.GetEnvironmentVariable("GUARD_TEST_POSTGRES") is { Length: > 0 } server ? server : "Host=localhost;Port=5432;Username=postgres;Password=postgres";

    private readonly IAbpApplicationWithInternalServiceProvider _app;

    private NotifyApp(IAbpApplicationWithInternalServiceProvider app) => _app = app;

    public IServiceProvider Services => _app.ServiceProvider;

    public T Get<T>() where T : notnull => Services.GetRequiredService<T>();

    public Messenger Messenger => Get<Messenger>();

    public People People => Get<People>();

    public Chat Chat => Get<Chat>();

    /// <summary>One round of the sender, as each server's does every second.</summary>
    public Task RoundAsync() => ActivatorUtilities.CreateInstance<NoticeSender>(Services).RoundAsync(default);

    public static async Task<NotifyApp> StartAsync(Dictionary<string, string?>? settings = null)
    {
        string database = "abp_notify_" + Guid.NewGuid().ToString("N")[..12];
        Dictionary<string, string?> all = new(settings ?? []) { ["ConnectionStrings:Default"] = $"{Server};Database={database}" };
        IConfiguration configuration = new ConfigurationBuilder().AddInMemoryCollection(all).Build();
        IAbpApplicationWithInternalServiceProvider app = await AbpApplicationFactory.CreateAsync<NotifyHost>(o =>
        {
            o.UseAutofac();
            o.Services.ReplaceConfiguration(configuration);
        });
        await app.InitializeAsync();
        NotifyApp notify = new(app);
        await notify.RunAsync(async db => await db.Database.EnsureCreatedAsync());
        return notify;
    }

    public async Task<T> RunAsync<T>(Func<HostDb, Task<T>> work)
    {
        await using AsyncServiceScope scope = Services.CreateAsyncScope();
        return await work((HostDb)scope.ServiceProvider.GetRequiredService<INotifyDbContext>());
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

[ConnectionStringName("Default")]
public sealed class HostDb(DbContextOptions<HostDb> options) : AbpDbContext<HostDb>(options), IConnectionsDbContext, INotifyDbContext
{
    public DbSet<Connection> Connections => Set<Connection>();
    public DbSet<ConnectionAccount> ConnectionAccounts => Set<ConnectionAccount>();
    public DbSet<Notice> Notices => Set<Notice>();
    public DbSet<NotificationSettings> NotificationSettings => Set<NotificationSettings>();
    public DbSet<NoticeSiteSettings> NoticeSiteSettings => Set<NoticeSiteSettings>();
    public DbSet<ChannelAddress> ChannelAddresses => Set<ChannelAddress>();
    public DbSet<ChannelTarget> ChannelTargets => Set<ChannelTarget>();
    public DbSet<ChannelPost> ChannelPosts => Set<ChannelPost>();
    public DbSet<PersonDevice> Devices => Set<PersonDevice>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ConfigureConnections("outside");
        builder.ConfigureNotify("told", new NotifyColumns("ProjectId", "RecordId", "RecordKey"));
    }
}

[DependsOn(typeof(AbpNotifyModule), typeof(AbpEntityFrameworkCorePostgreSqlModule), typeof(AbpAutofacModule))]
public sealed class NotifyHost : AbpModule
{
    public override void ConfigureServices(ServiceConfigurationContext context)
    {
        context.Services.AddAbpDbContext<HostDb>(options =>
        {
            options.ReplaceDbContext<IConnectionsDbContext>();
            options.ReplaceDbContext<INotifyDbContext>();
        });
        Configure<AbpDbContextOptions>(options => options.UseNpgsql());
        context.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
        context.Services.Configure<NoticeEventOptions>(o => o.Add(["status", "mentioned"]));
        context.Services.AddSingleton<Messenger>();
        context.Services.AddSingleton<INotifyMessenger>(sp => sp.GetRequiredService<Messenger>());
        context.Services.AddSingleton<People>();
        context.Services.AddSingleton<INotifyPeople>(sp => sp.GetRequiredService<People>());
        context.Services.AddSingleton<INoticeDigests, Digests>();
        context.Services.AddSingleton<INotifyChannel, Mail>();
        context.Services.AddSingleton<INotifyChannel, Sms>();
        context.Services.AddSingleton<Chat>();
        context.Services.AddHttpClient(new NotifyOptions().HttpClientName).ConfigurePrimaryHttpMessageHandler(sp => new ChatHandler(sp.GetRequiredService<Chat>()));
    }
}

/// <summary>A message the application was asked to send.</summary>
public sealed record Sent(NotifyMessage Message);

/// <summary>
/// The application's messenger: keeps what it was asked to send. It has the templates the tests name, a short form for
/// <c>status</c>, and reaches on <c>sms</c> only the addresses <see cref="Unreachable"/> doesn't hold.
/// </summary>
public sealed class Messenger : INotifyMessenger
{
    public ConcurrentQueue<Sent> Log { get; } = new();

    public IReadOnlyList<NotifyMessage> Messages => [.. Log.Select(s => s.Message)];

    public HashSet<string> Templates { get; } = ["status", "status.message", "notice.digest", ChannelAddressBook.CodeTemplate];

    public bool SmsUnreachable { get; set; }

    public bool HasTemplate(string key) => Templates.Contains(key);

    public Task<NotifySent> SendAsync(NotifyMessage message, CancellationToken cancellationToken)
    {
        if (!HasTemplate(message.Template))
        {
            throw new InvalidOperationException($"There's no template '{message.Template}'.");
        }

        Log.Enqueue(new Sent(message));
        int unreachable = message.Channel == Sms.ChannelKey && SmsUnreachable ? message.To.Count : 0;
        return Task.FromResult(new NotifySent(message.To.Count - unreachable, 0, 0, unreachable, unreachable == message.To.Count ? [] : [Guid.NewGuid()]));
    }
}

/// <summary>The application's people, as the tests add them.</summary>
public sealed class People : INotifyPeople
{
    public ConcurrentDictionary<Guid, NotifyPerson> Known { get; } = new();

    public string SiteTimeZone => "UTC";

    public Guid Add(string name, string? timeZone = null)
    {
        Guid id = Guid.NewGuid();
        Known[id] = new NotifyPerson(id, name, $"{name.ToLowerInvariant()}@example.com", "en", timeZone);
        return id;
    }

    public Task<IReadOnlyList<NotifyPerson>> PeopleAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<NotifyPerson>>([.. ids.Where(Known.ContainsKey).Select(id => Known[id])]);

    public Task<IReadOnlyDictionary<Guid, string>> NamesAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyDictionary<Guid, string>>(ids.Where(Known.ContainsKey).ToDictionary(id => id, id => Known[id].Name));
}

/// <summary>A digest's model: how many, and their summaries.</summary>
public sealed class Digests : INoticeDigests
{
    public IReadOnlyDictionary<string, object?> Model(IReadOnlyList<Notice> notices, bool digest) =>
        new Dictionary<string, object?> { ["digest"] = digest, ["count"] = notices.Count, ["summaries"] = notices.Select(n => n.Summary).ToList() };
}

/// <summary>The application's mail: everyone with an email.</summary>
public sealed class Mail : INotifyChannel
{
    public string Key => "email";
    public IReadOnlyList<string> Kinds => [NotifyTemplateKinds.Email];
    public Task<bool> ReadyAsync(CancellationToken cancellationToken) => Task.FromResult(true);
    public bool IsAddress(string address) => address.Contains('@');
    public Task<string?> AddressAsync(NotifyPerson person, CancellationToken cancellationToken) => Task.FromResult(person.Email);
    public Task DeliverAsync(NotifyDelivery delivery, CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>A channel people type their address on, as a plugin would add: a phone number.</summary>
public sealed class Sms(INotifyAddresses addresses) : INotifyChannel, IPersonalNotifyChannel
{
    public const string ChannelKey = "sms";
    public string Key => ChannelKey;
    public string Name => "SMS";
    public bool PeopleTypeAddress => true;
    public string? AddressHint => "+966500000000";
    public IReadOnlyList<string> Kinds => [NotifyTemplateKinds.Message];
    public Task<bool> ReadyAsync(CancellationToken cancellationToken) => Task.FromResult(true);
    public bool IsAddress(string address) => address.StartsWith('+');
    public Task<string?> AddressAsync(NotifyPerson person, CancellationToken cancellationToken) => addresses.AddressAsync(person.Id, ChannelKey, cancellationToken);
    public Task DeliverAsync(NotifyDelivery delivery, CancellationToken cancellationToken) => Task.CompletedTask;

    public string? Normalize(string address)
    {
        string digits = new([.. address.Where(c => char.IsDigit(c) || c == '+')]);
        return digits.StartsWith('+') && digits.Length is >= 8 and <= 16 ? digits : null;
    }
}

/// <summary>A chat service's API, as Slack's: what was posted where.</summary>
public sealed class Chat
{
    public ConcurrentQueue<(string Url, string Body)> Calls { get; } = new();
}

internal sealed class ChatHandler(Chat chat) : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        chat.Calls.Enqueue((request.RequestUri!.ToString(), request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken)));
        return new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StringContent("""{"ok":true,"ts":"1.2"}""", Encoding.UTF8, "application/json") };
    }
}
