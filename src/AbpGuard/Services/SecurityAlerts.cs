using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using AbpGuard.Domain;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>
/// What alerts site admins, and how much makes a burst. The host adds its own events to
/// <see cref="EveryEventOf"/> (a backup downloaded).
/// </summary>
public sealed class SecurityAlertOptions
{
    /// <summary>Failed sign-ins in <see cref="Window"/> that make a burst.</summary>
    public int FailedSignIns { get; set; } = 20;

    /// <summary>Exports of people's data and of queries in an hour that make a mass export.</summary>
    public int Exports { get; set; } = 5;

    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>The least time between two alerts of one kind: a burst is told once.</summary>
    public TimeSpan Quiet { get; set; } = TimeSpan.FromHours(1);

    /// <summary>A feed failing this long is told (feed-failing).</summary>
    public TimeSpan FeedFailing { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Events each of which is told (once per check, counted): sign-ins blocked, apps added, a person's data exported by an admin.</summary>
    public List<string> EveryEventOf { get; set; } =
        ["auth.login.blocked", "oauth.app.created", "privacy.export.account", "privacy.export.address"];
}

/// <summary>An alert as a site admin is told it: what happened, how many times since when.</summary>
public sealed record SecurityAlert(string Kind, int Count, DateTime Since);

/// <summary>
/// Tells site admins, through the messages they already get (<see cref="IGuardMessenger"/>), of what may be a breach
/// (PDPL): a burst of failed sign-ins, sign-ins blocked, a new site admin, a token or an app an admin
/// made, a person's data exported by an admin, many exports in an hour, a feed that keeps failing, and the host's own (a
/// backup downloaded). A new site admin is seen when someone (or a group) is added to the admins group, or granted the
/// Administrator role; not when a directory's sync adds someone to a group that holds admin rights, nor when someone
/// joins a group nested in admins: site admins look for those in the directory and on the groups' pages. A
/// check every five minutes reads the security log since the last; each kind is told at most once an hour, with how
/// many times it happened. Each alert sent goes in the log too.
/// </summary>
public sealed class SecurityAlerts(GuardDb guardDb, IGuardMessenger messenger, IGuardSiteDefaults site, SecurityLog audit, IOptions<GuardOptions> options)
    : ITransientDependency
{
    public const string MessageKind = "guard.security-alert";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>Checks the log since the last check; returns the alerts it told.</summary>
    public async Task<List<SecurityAlert>> CheckAsync(CancellationToken ct)
    {
        SecurityAlertOptions o = options.Value.SecurityAlerts;
        DateTime now = DateTime.UtcNow;
        (List<SecurityAlert> due, List<(Guid Id, string Username, string? Email, string? Language)> admins) = await guardDb.RunAsync(async db =>
        {
            // The first check looks back a window, so what happened before it (since the site started, or was upgraded) is told.
            SecurityAlertState state = await db.SecurityAlertStates.FirstOrDefaultAsync(ct)
                ?? db.SecurityAlertStates.Add(new SecurityAlertState { CheckedUpTo = now - o.Window }).Entity;
            DateTime since = state.CheckedUpTo;
            Dictionary<string, DateTime> sent = JsonSerializer.Deserialize<Dictionary<string, DateTime>>(state.Sent, Json) ?? [];
            List<SecurityAlert> found = [];

            int failed = await db.SecurityEvents.CountAsync(e => e.Type == "auth.login.failed" && e.Time > now - o.Window, ct);
            if (failed >= o.FailedSignIns)
            {
                found.Add(new SecurityAlert("failed-sign-ins", failed, now - o.Window));
            }

            int exports = await db.SecurityEvents.CountAsync(e => (e.Type.StartsWith("privacy.export.") || e.Type == SecurityAuditTypes.QueryExport) && e.Time > now.AddHours(-1), ct);
            if (exports >= o.Exports)
            {
                found.Add(new SecurityAlert("mass-export", exports, now.AddHours(-1)));
            }

            string admins = GuardConstants.AdminsGroupId.ToString();
            int newAdmins = await db.SecurityEvents.CountAsync(e => e.Type == SecurityAuditTypes.MembershipAdded && e.Time > since && e.Detail != null && e.Detail.Contains(admins), ct);
            if (newAdmins > 0)
            {
                found.Add(new SecurityAlert("new-admin", newAdmins, since));
            }

            string administrator = GuardRoles.AdministratorId.ToString();
            int granted = await db.SecurityEvents.CountAsync(e => e.Type == SecurityAuditTypes.GrantAdded && e.Time > since && e.Detail != null && e.Detail.Contains(administrator), ct);
            if (newAdmins + granted > 0)
            {
                found.RemoveAll(a => a.Kind == "new-admin");
                found.Add(new SecurityAlert("new-admin", newAdmins + granted, since));
            }

            if (await db.SecurityFeeds.AsNoTracking().Where(f => f.Enabled && f.FailingSince != null && f.FailingSince < now - o.FeedFailing)
                    .Select(f => f.FailingSince).FirstOrDefaultAsync(ct) is { } failing)
            {
                found.Add(new SecurityAlert("feed-failing", 1, failing));
            }

            int tokens = await db.SecurityEvents.CountAsync(e => e.Type == SecurityAuditTypes.TokenCreated && e.Time > since && e.TargetId != null && e.AccountId != e.TargetId, ct);
            if (tokens > 0)
            {
                found.Add(new SecurityAlert("token-by-admin", tokens, since));
            }

            foreach (string type in o.EveryEventOf)
            {
                int count = await db.SecurityEvents.CountAsync(e => e.Type == type && e.Time > since, ct);
                if (count > 0)
                {
                    found.Add(new SecurityAlert(type, count, since));
                }
            }

            List<SecurityAlert> tell = [.. found.Where(a => !sent.TryGetValue(a.Kind, out DateTime last) || now - last >= o.Quiet)];
            foreach (SecurityAlert alert in tell)
            {
                sent[alert.Kind] = now;
            }

            (state.CheckedUpTo, state.Sent) = (now, JsonSerializer.Serialize(sent, Json));
            await db.SaveChangesAsync(ct);
            // The admins group's members, as accounts and as directory records (a nested group's aren't told).
            List<Guid> records = await db.Memberships.AsNoTracking().Where(m => m.GroupId == GuardConstants.AdminsGroupId && m.MemberType == MemberType.DirectoryUser)
                .Select(m => m.MemberId).ToListAsync(ct);
            List<string> usernames = await db.DirectoryUsers.AsNoTracking().Where(u => records.Contains(u.Id)).Select(u => u.NormalizedUsername).ToListAsync(ct);
            List<Guid> members = [.. await db.Memberships.AsNoTracking().Where(m => m.GroupId == GuardConstants.AdminsGroupId && m.MemberType == MemberType.Account)
                    .Select(m => m.MemberId).ToListAsync(ct),
                .. await db.Accounts.AsNoTracking().Where(a => usernames.Contains(a.NormalizedUsername)).Select(a => a.Id).ToListAsync(ct)];
            List<(Guid, string, string?, string?)> people = [.. (await db.Accounts.AsNoTracking()
                    .Where(a => members.Contains(a.Id) && a.Status == AccountStatus.Active && !a.IsService).ToListAsync(ct))
                .Select(a => (a.Id, a.Username, a.MailAddress, a.Language))];
            return (tell, people);
        }, requiresNew: true, ct);

        foreach (SecurityAlert alert in due)
        {
            foreach ((Guid id, string username, string? email, string? language) in admins)
            {
                await messenger.SendAsync(new GuardMessage(MessageKind, id, email, username, new Dictionary<string, object?>
                {
                    ["what"] = alert.Kind,
                    ["count"] = alert.Count,
                    ["since"] = alert.Since.ToString("u", System.Globalization.CultureInfo.InvariantCulture),
                    ["link"] = GuardPageOptions.Link(options.Value.PublicUrl?.TrimEnd('/') ?? "", options.Value.Pages.SecurityLog, language ?? site.RequestLanguage),
                }, language ?? site.RequestLanguage, "security-alert"), ct);
            }

            await audit.WriteAsync(SecurityAuditTypes.AlertSent, null, new { alert.Kind, alert.Count, admins = admins.Count }, ct);
        }

        return due;
    }

    private static Dictionary<string, string> Text(string en, string ar) => new() { ["en"] = en, ["ar"] = ar };

    /// <summary>The message site admins get, rewordable as any of Guard's.</summary>
    public static readonly GuardMessageTemplate Definition = new(
        MessageKind,
        Email: true,
        Text("A security alert", "تنبيه أمني"),
        Text("Sent to site admins when the security log shows what may be a breach, at most once an hour for each kind.",
            "تُرسل إلى مشرفي الموقع حين يُظهر سجل الأمان ما قد يكون اختراقًا، مرة في الساعة على الأكثر لكل نوع."),
        new Dictionary<string, GuardTemplateText>
        {
            ["en"] = new("Security alert: {{ what }}",
                "Hello,\n\nThe security log shows {{ count }} × {{ what }} since {{ since }}. Look at it now: {{ link }}\n\n"
                + "If it may be a breach, follow your site's breach runbook: who to tell, and within 72 hours."),
            ["ar"] = new("تنبيه أمني: {{ what }}",
                "مرحبًا،\n\nيُظهر سجل الأمان {{ count }} × {{ what }} منذ {{ since }}. اطّلع عليه الآن: {{ link }}\n\n"
                + "إن كان قد يكون اختراقًا، فاتّبع دليل موقعك للاختراقات: من تُخبر، وخلال 72 ساعة."),
        },
        [
            new("what", Text("What happened", "ما حدث")),
            new("count", Text("How many times", "عدد المرات")),
            new("since", Text("Since when", "منذ متى")),
            new("link", Text("The security log's page", "صفحة سجل الأمان")),
        ],
        new Dictionary<string, object?> { ["what"] = "failed-sign-ins", ["count"] = 42, ["since"] = "2026-11-01 09:00:00Z", ["link"] = "https://example.com/admin/security" });
}

/// <summary>Checks for alerts every five minutes, on one server at a time.</summary>
public sealed class SecurityAlertsWorker(IServiceScopeFactory scopes, IGuardLocks locks, IOptions<GuardOptions> options, ILogger<SecurityAlertsWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using PeriodicTimer timer = new(TimeSpan.FromMinutes(5));
        while (options.Value.Features.SecurityAlerts && await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await using IAsyncDisposable? held = await locks.TryTakeAsync("security-alerts", stoppingToken);
                if (held is not null)
                {
                    await using AsyncServiceScope scope = scopes.CreateAsyncScope();
                    await scope.ServiceProvider.GetRequiredService<SecurityAlerts>().CheckAsync(stoppingToken);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Checking for security alerts failed; it checks again in five minutes.");
            }
        }
    }
}
