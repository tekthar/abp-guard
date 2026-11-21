using System.Text.Json.Nodes;
using AbpConnections;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Volo.Abp.DependencyInjection;
using Volo.Abp.Modularity;

namespace AbpNotify;

/// <summary>
/// Notices, people's channels, phones and teams' channels. The application lists this module in its DependsOn, maps the
/// tables in its own context (<see cref="NotifyModel.ConfigureNotify"/>, the context implementing
/// <see cref="INotifyDbContext"/> and standing in for it), and fills the seams: <see cref="INotifyMessenger"/> (it renders
/// its templates and sends, keeping its outbox), <see cref="INotifyPeople"/> and <see cref="INoticeDigests"/>, and its
/// mail channel among the <see cref="INotifyChannel"/>s (key <see cref="NotifyOptions.MailChannel"/>). Its modules add
/// the events people choose for (<see cref="NoticeEventOptions"/>). The sender runs on every server; the site's defaults
/// are read from <c>Notices</c> (<see cref="NoticeOptions"/>). Slack, Teams and push call out with
/// <see cref="NotifyOptions.HttpClientName"/>, guarded by AbpConnections' outbound guard, with a 30-second timeout.
/// </summary>
[DependsOn(typeof(AbpConnectionsModule))]
public class AbpNotifyModule : AbpModule
{
    public override void ConfigureServices(ServiceConfigurationContext context)
    {
        // Defaults a host replaces by registering its own.
        context.Services.TryAddTransient<INotifyChannels, ServiceNotifyChannels>();
        context.Services.TryAddTransient<IPushMessages, PlainPushMessages>();
        context.Services.AddOptions<NotifyOptions>();
        context.Services.Configure<NoticeOptions>(context.Services.GetConfiguration().GetSection("Notices"));
        context.Services.AddHttpClient(new NotifyOptions().HttpClientName, client => client.Timeout = TimeSpan.FromSeconds(30)).RefusePrivateAddresses();
        context.Services.AddHostedService<NoticeSender>();
    }
}

/// <summary>
/// The channels registered as services (<see cref="INotifyChannel"/>), each under its own key. They're made when leased,
/// not with this: a channel reaches people's addresses and connections, which reach back to the channels.
/// </summary>
public sealed class ServiceNotifyChannels(IServiceProvider services) : INotifyChannels
{
    public Task<INotifyChannelsLease> LeaseAsync(CancellationToken cancellationToken) =>
        Task.FromResult<INotifyChannelsLease>(new Lease([.. services.GetServices<INotifyChannel>().Select(c => new NotifyChannelEntry(c.Key, c, null))]));

    private sealed class Lease(IReadOnlyList<NotifyChannelEntry> items) : INotifyChannelsLease
    {
        public IReadOnlyList<NotifyChannelEntry> Items { get; } = items;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

/// <summary>
/// A push as any app can show it: titled with the message's subject (the application's name without one), saying its
/// text, and carrying the message's id as <c>noticeId</c>. An application whose app opens what a notice is about
/// registers its own <see cref="IPushMessages"/>.
/// </summary>
public sealed class PlainPushMessages(IOptions<NotifyOptions> options) : IPushMessages
{
    public const int MaxTitle = 200;
    public const int MaxBody = 1000;

    public JsonObject Message(NotifyDelivery delivery, string token) => new()
    {
        ["token"] = token,
        ["notification"] = new JsonObject
        {
            ["title"] = Cut(string.IsNullOrWhiteSpace(delivery.Subject) ? options.Value.ApplicationName : delivery.Subject.Trim(), MaxTitle),
            ["body"] = Cut(delivery.Text.Trim(), MaxBody),
        },
        ["data"] = new JsonObject { ["noticeId"] = delivery.Id.ToString() },
        ["android"] = new JsonObject { ["priority"] = "high" },
        ["apns"] = new JsonObject { ["headers"] = new JsonObject { ["apns-priority"] = "10" } },
    };

    private static string Cut(string text, int max) => text.Length > max ? text[..(max - 1)].TrimEnd() + "…" : text;
}

/// <summary>A Slack or Teams connection isn't removed while a team's channel posts through it.</summary>
[ExposeServices(typeof(IConnectionUses))]
public sealed class ChannelTargetConnectionUses(ChannelTargetStore store) : IConnectionUses, ITransientDependency
{
    public Task<IReadOnlyList<string>> UsesAsync(Guid connectionId, CancellationToken cancellationToken) => store.UsesAsync(connectionId, cancellationToken);
}
