using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AbpNotify;

/// <summary>
/// Sends notices as each person chose. What's to be told now goes at once, unless they had a message within the site's
/// window: then what gathers goes together when the window ends, so a burst of changes is one message. A notice meant
/// to go alone (a mention) goes at once, on its own, whatever the window. Past the site's messages an hour, the rest go
/// to their digest. Their digest comes hourly, or daily at their hour, in their time zone. In their quiet hours nothing
/// goes; what waited goes together when they end. A message's notices are claimed (<see cref="Notice.MailId"/>) before
/// it's sent, so two servers never send one notice twice. For someone who hears by a chat channel, what's told now
/// goes there in its short form, and by mail when it can't reach them; their digest comes by mail.
/// </summary>
public sealed class NoticeSender(IServiceScopeFactory scopes, NoticeWakeup wakeup, IOptions<NotifyOptions> options, ILogger<NoticeSender> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RoundAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "The notices' round failed");
            }

            await wakeup.WaitAsync(TimeSpan.FromSeconds(1), stoppingToken);
        }
    }

    /// <summary>One look at everyone with something to be told.</summary>
    internal async Task RoundAsync(CancellationToken ct)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        IServiceProvider services = scope.ServiceProvider;
        INotifyDbContext db = services.GetRequiredService<INotifyDbContext>();
        List<Guid> waiting = await db.Notices.AsNoTracking().Where(n => n.SentAt == null && n.MailId == null).Select(n => n.AccountId).Distinct().Take(500).ToListAsync(ct);
        if (waiting.Count == 0)
        {
            return;
        }

        NoticeStore store = services.GetRequiredService<NoticeStore>();
        NoticeSiteSettingsDto site = await store.SiteAsync(ct);
        Dictionary<Guid, NotificationSettings> chosen = await store.SettingsAsync(waiting, ct);
        INotifyPeople known = services.GetRequiredService<INotifyPeople>();
        Dictionary<Guid, NotifyPerson> people = (await known.PeopleAsync(waiting, ct)).ToDictionary(p => p.Id);
        DateTime now = DateTime.UtcNow;
        foreach (Guid account in waiting)
        {
            NotificationSettings settings = chosen.GetValueOrDefault(account) ?? new NotificationSettings { AccountId = account };
            TimeZoneInfo zone = Zone(people.GetValueOrDefault(account)?.TimeZone ?? known.SiteTimeZone);
            if (settings.Quiet(now, zone))
            {
                continue;
            }

            List<Notice> pending = await db.Notices.AsNoTracking().Where(n => n.AccountId == account && n.SentAt == null && n.MailId == null)
                .OrderBy(n => n.CreatedAt).ToListAsync(ct);
            List<Notice> soon = [.. pending.Where(n => n.Delivery == NoticeChoices.Now)];
            if (soon.Count > 0)
            {
                IQueryable<Notice> sent = db.Notices.AsNoTracking().Where(n => n.AccountId == account && n.Delivery == NoticeChoices.Now && n.SentAt != null);
                int lastHour = await sent.Where(n => n.SentAt > now.AddHours(-1)).Select(n => n.MailId).Distinct().CountAsync(ct);
                DateTime? last = await sent.MaxAsync(n => n.SentAt, ct);
                if (lastHour >= site.MailsPerHour)
                {
                    // Enough this hour: the rest wait for their digest.
                    List<Guid> ids = [.. soon.Select(n => n.Id)];
                    await db.Notices.Where(n => ids.Contains(n.Id)).ExecuteUpdateAsync(u => u.SetProperty(n => n.Delivery, NoticeChoices.Digest), ct);
                }
                else
                {
                    foreach (Notice alone in soon.Where(n => n.Alone))
                    {
                        await SendAsync(services, db, account, [alone], digest: false, settings, ct);
                    }

                    List<Notice> together = [.. soon.Where(n => !n.Alone)];
                    if (together.Count > 0 && (last is null || now - last >= TimeSpan.FromSeconds(site.WindowSeconds)))
                    {
                        await SendAsync(services, db, account, together, digest: false, settings, ct);
                    }
                }
            }

            List<Notice> later = [.. pending.Where(n => n.Delivery == NoticeChoices.Digest)];
            if (later.Count > 0 && settings.DigestDue(now, zone) && await SendAsync(services, db, account, later, digest: true, settings, ct))
            {
                await db.NotificationSettings.Where(s => s.AccountId == account).ExecuteUpdateAsync(u => u.SetProperty(s => s.LastDigestAt, now), ct);
                if (!chosen.ContainsKey(account))
                {
                    // Someone who never chose still has a digest clock.
                    db.NotificationSettings.Add(new NotificationSettings { AccountId = account, LastDigestAt = now });
                    await db.SaveChangesAsync(ct);
                }
            }
        }
    }

    /// <summary>
    /// Sends these notices in one message: one alone in its own words; several, or a digest, as a list by what they're
    /// about. False when another server took them first, or the message couldn't be queued (they wait for the next round).
    /// </summary>
    private async Task<bool> SendAsync(IServiceProvider services, INotifyDbContext db, Guid account, List<Notice> notices, bool digest, NotificationSettings settings,
        CancellationToken ct)
    {
        Guid mailId = Guid.NewGuid();
        List<Guid> ids = [.. notices.Select(n => n.Id)];
        await db.Notices.Where(n => ids.Contains(n.Id) && n.MailId == null && n.SentAt == null).ExecuteUpdateAsync(u => u.SetProperty(n => n.MailId, mailId), ct);
        List<Notice> claimed = await db.Notices.AsNoTracking().Where(n => n.MailId == mailId).OrderBy(n => n.CreatedAt).ToListAsync(ct);
        if (claimed.Count == 0)
        {
            return false;
        }

        try
        {
            NotifyOptions names = options.Value;
            Notice first = claimed[0];
            NotifyMessage message = claimed.Count == 1 && !digest && first.Template is { } template
                ? new NotifyMessage(template, [NotifyRecipient.Person(account)], Notice.Model(first.ModelJson), null, first.ScopeId, first.SubjectId, first.SubjectKey,
                    Source: first.Source ?? "notice", Later: true)
                : new NotifyMessage(names.DigestTemplate, [NotifyRecipient.Person(account)], services.GetRequiredService<INoticeDigests>().Model(claimed, digest),
                    Source: digest ? "notice:digest" : "notice:batch", Later: true);
            INotifyMessenger messenger = services.GetRequiredService<INotifyMessenger>();
            // For someone who hears by a chat channel, what's told now goes there as a short message, alone or
            // gathered; by mail when it can't reach them. Their digest comes by mail.
            if (!digest && settings.Channel != names.MailChannel && messenger.HasTemplate(message.Template + names.ShortSuffix))
            {
                NotifySent? chat = null;
                try
                {
                    chat = await messenger.SendAsync(message with { Template = message.Template + names.ShortSuffix, Channel = settings.Channel }, ct);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogWarning(ex, "{Account}'s channel {Channel} can't take notices now; they go by mail.", account, settings.Channel);
                }

                if (chat is { Unreachable: 0, Messages.Count: > 0 })
                {
                    await db.Notices.Where(n => n.MailId == mailId).ExecuteUpdateAsync(u => u.SetProperty(n => n.SentAt, DateTime.UtcNow), ct);
                    return true;
                }
            }

            await messenger.SendAsync(message, ct);
            await db.Notices.Where(n => n.MailId == mailId).ExecuteUpdateAsync(u => u.SetProperty(n => n.SentAt, DateTime.UtcNow), ct);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await db.Notices.Where(n => n.MailId == mailId).ExecuteUpdateAsync(u => u.SetProperty(n => n.MailId, (Guid?)null), CancellationToken.None);
            logger.LogWarning(ex, "Notices for {Account} weren't sent; they'll be tried again.", account);
            return false;
        }
    }

    private static TimeZoneInfo Zone(string id) => TimeZoneInfo.TryFindSystemTimeZoneById(id, out TimeZoneInfo? zone) ? zone : TimeZoneInfo.Utc;
}
