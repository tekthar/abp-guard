using System.Text.Json.Serialization;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Volo.Abp;
using Volo.Abp.DependencyInjection;
using Volo.Abp.Domain.Entities;

namespace AbpNotify;

public sealed record NotificationSettingsDto(Dictionary<string, string> Choices, bool AutoWatch, bool OwnChanges, string DigestEvery, int DigestHour,
    string? QuietFrom, string? QuietTo, string Channel, List<string> Events, List<string> ChoicesOffered);

public sealed record NotificationSettingsInput(Dictionary<string, string>? Choices, [property: JsonRequired] bool AutoWatch, [property: JsonRequired] bool OwnChanges, string? DigestEvery = null, int? DigestHour = null,
    string? QuietFrom = null, string? QuietTo = null, string? Channel = null);

/// <summary>A notice as its person sees it in their inbox: what it's about (a subject's key) or where it leads, and who acted.</summary>
public sealed record NoticeView(Guid Id, string Event, string? SubjectKey, string Reason, string Delivery, string Summary, Guid? ActorId, string? ActorName,
    DateTime CreatedAt, DateTime? SentAt, DateTime? ReadAt, string? Link);

/// <summary>A person's inbox: their notices, newest first, and how many they haven't read.</summary>
public sealed record InboxView(List<NoticeView> Items, int Unread);

/// <summary>Marks notices read: these, or all of them.</summary>
public sealed record InboxReadInput(List<Guid>? Ids, bool All = false);

public sealed record NoticeSiteSettingsDto([property: JsonRequired] int WindowSeconds, [property: JsonRequired] int MailsPerHour);

/// <summary>
/// The notices people were told and their own choices, for every module: each claims a notice once per event and
/// person, and the sender sends it as the person chose. The inbox reads them.
/// </summary>
public sealed class NoticeStore(IServiceScopeFactory scopes, IServiceProvider services, NoticeWakeup wakeup, IOptions<NoticeEventOptions> events,
    IOptions<NoticeOptions> options, IOptions<NotifyOptions> notify) : ITransientDependency
{
    /// <summary>Writes the notice for the sender to send; false when this event already told this person.</summary>
    public async Task<bool> ClaimAsync(Notice n, CancellationToken ct)
    {
        bool claimed = await InsertAsync(n, n.Delivery, sentAt: null, ct);
        if (claimed)
        {
            wakeup.Signal();
        }

        return claimed;
    }

    /// <summary>
    /// Writes a notice its sender already told by a message of its own (<see cref="NoticeChoices.Told"/>, whatever its
    /// delivery said): the inbox has it, and the sender never sends it. False when this event already told this person.
    /// </summary>
    public Task<bool> KeepToldAsync(Notice n, CancellationToken ct) => InsertAsync(n, NoticeChoices.Told, n.CreatedAt, ct);

    private async Task<bool> InsertAsync(Notice n, string delivery, DateTime? sentAt, CancellationToken ct)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        INotifyDbContext db = scope.ServiceProvider.GetRequiredService<INotifyDbContext>();
        NotifyTable t = NotifyTable.Of<Notice>(db);
        string columns = t.Columns(nameof(Notice.Id), nameof(Notice.EventId), nameof(Notice.AccountId), nameof(Notice.Event), nameof(Notice.Reason), nameof(Notice.ActorId),
            nameof(Notice.Delivery), nameof(Notice.Summary), nameof(Notice.ScopeId), nameof(Notice.SubjectId), nameof(Notice.SubjectKey), nameof(Notice.Link),
            nameof(Notice.Template), nameof(Notice.ModelJson), nameof(Notice.Source), nameof(Notice.Alone), nameof(Notice.CreatedAt), nameof(Notice.SentAt));
#pragma warning disable CS8601 // a null goes as SQL NULL; EF Core's signature says object
        return await db.Database.ExecuteSqlRawAsync($$"""
            INSERT INTO {{t.Name}} ({{columns}})
            VALUES ({0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}, {11}, {12}, {13}::jsonb, {14}, {15}, {16}, {17})
            ON CONFLICT ({{t.Columns(nameof(Notice.EventId), nameof(Notice.AccountId))}}) DO NOTHING
            """, [n.Id, n.EventId, n.AccountId, n.Event, n.Reason, n.ActorId, delivery, n.Summary, n.ScopeId, n.SubjectId, n.SubjectKey, n.Link, n.Template, n.ModelJson,
                n.Source, n.Alone, n.CreatedAt, sentAt], ct) == 1;
#pragma warning restore CS8601
    }

    /// <summary>Adds a subject's key to a held notice (a bulk change's, for this person), once.</summary>
    public async Task AppendHeldAsync(Guid eventId, Guid accountId, string subjectKey, CancellationToken ct)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        INotifyDbContext db = scope.ServiceProvider.GetRequiredService<INotifyDbContext>();
        NotifyTable t = NotifyTable.Of<Notice>(db);
        string model = t[nameof(Notice.ModelJson)];
        await db.Database.ExecuteSqlRawAsync($$"""
            UPDATE {{t.Name}} SET {{model}} = jsonb_set({{model}}, ARRAY['keys'], COALESCE({{model}}->'keys', '[]'::jsonb) || to_jsonb({0}::text))
            WHERE {{t[nameof(Notice.EventId)]}} = {1} AND {{t[nameof(Notice.AccountId)]}} = {2} AND {{t[nameof(Notice.Delivery)]}} = {3}
              AND NOT COALESCE({{model}}->'keys', '[]'::jsonb) ? {4}
            """, [subjectKey, eventId, accountId, NoticeChoices.Held, subjectKey], ct);
    }

    /// <summary>
    /// Releases an event's held notices (a bulk change ended): each gets its own delivery back (kept in its model as
    /// <c>delivery</c>), and what <paramref name="settle"/> says it now reads: a summary and a model.
    /// </summary>
    public async Task<int> ReleaseHeldAsync(Guid eventId, Func<Notice, JsonObject, (string Summary, JsonObject Model)> settle, CancellationToken ct)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        INotifyDbContext db = scope.ServiceProvider.GetRequiredService<INotifyDbContext>();
        NotifyTable t = NotifyTable.Of<Notice>(db);
        List<Notice> held = await db.Notices.AsNoTracking().Where(n => n.EventId == eventId && n.Delivery == NoticeChoices.Held).ToListAsync(ct);
        foreach (Notice n in held)
        {
            JsonObject model = (n.ModelJson is null ? null : JsonNode.Parse(n.ModelJson) as JsonObject) ?? [];
            string delivery = (string?)model["delivery"] is NoticeChoices.Digest ? NoticeChoices.Digest : NoticeChoices.Now;
            (string summary, JsonObject settled) = settle(n, model);
            string json = settled.ToJsonString();
            await db.Database.ExecuteSqlRawAsync($$"""
                UPDATE {{t.Name}} SET {{t[nameof(Notice.Delivery)]}} = {0}, {{t[nameof(Notice.Summary)]}} = {1}, {{t[nameof(Notice.ModelJson)]}} = {2}::jsonb,
                    {{t[nameof(Notice.CreatedAt)]}} = {3}
                WHERE {{t[nameof(Notice.Id)]}} = {4} AND {{t[nameof(Notice.Delivery)]}} = {5}
                """, [delivery, summary, json, DateTime.UtcNow, n.Id, NoticeChoices.Held], ct);
        }

        if (held.Count > 0)
        {
            wakeup.Signal();
        }

        return held.Count;
    }

    /// <summary>The choices of those who made any; everyone else hears by the defaults.</summary>
    public async Task<Dictionary<Guid, NotificationSettings>> SettingsAsync(IReadOnlyCollection<Guid> accountIds, CancellationToken ct)
    {
        if (accountIds.Count == 0)
        {
            return [];
        }

        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().NotificationSettings.AsNoTracking()
            .Where(s => accountIds.Contains(s.AccountId)).ToDictionaryAsync(s => s.AccountId, ct);
    }

    public async Task<NotificationSettings> SettingsAsync(Guid accountId, CancellationToken ct) =>
        (await SettingsAsync([accountId], ct)).GetValueOrDefault(accountId) ?? new NotificationSettings { AccountId = accountId };

    public async Task<NotificationSettingsDto> SettingsDtoAsync(Guid me, CancellationToken ct)
    {
        NotificationSettings s = await SettingsAsync(me, ct);
        return new NotificationSettingsDto(events.Value.Events.ToDictionary(e => e, s.ChoiceFor), s.AutoWatch, s.OwnChanges, s.DigestEvery, s.DigestHour,
            NotificationSettings.Clock(s.QuietFrom), NotificationSettings.Clock(s.QuietTo), s.Channel, [.. events.Value.Events], [.. NoticeChoices.All]);
    }

    public async Task<NotificationSettingsDto> SaveSettingsAsync(Guid me, NotificationSettingsInput input, CancellationToken ct)
    {
        Dictionary<string, string> choices = [];
        foreach ((string e, string choice) in input.Choices ?? [])
        {
            if (!events.Value.Events.Contains(e))
            {
                throw new UserFriendlyException($"\"{e}\" isn't an event to choose for; they are {string.Join(", ", events.Value.Events)}.");
            }

            if (!NoticeChoices.All.Contains(choice))
            {
                throw new UserFriendlyException($"Hear of {e} {string.Join(", ", NoticeChoices.All)}; not \"{choice}\".");
            }

            if (choice != NoticeChoices.Now)
            {
                choices[e] = choice; // now is the default, so it isn't kept
            }
        }

        string every = input.DigestEvery ?? DigestFrequencies.Daily;
        if (!DigestFrequencies.All.Contains(every))
        {
            throw new UserFriendlyException($"A digest comes {string.Join(" or ", DigestFrequencies.All)}; not \"{every}\".");
        }

        int hour = input.DigestHour ?? 8;
        if (hour is < 0 or > 23)
        {
            throw new UserFriendlyException("A daily digest's hour is 0 to 23.");
        }

        (int? quietFrom, int? quietTo) = (NotificationSettings.Minutes(input.QuietFrom), NotificationSettings.Minutes(input.QuietTo));
        if (quietFrom is null != quietTo is null)
        {
            throw new UserFriendlyException("Quiet hours need both a start and an end.");
        }

        string mail = notify.Value.MailChannel;
        string channel = input.Channel is { Length: > 0 } c ? c : mail;
        if (channel != mail && !(services.GetService<INotifyReach>() is { } reach && await reach.ReachesAsync(me, channel, ct)))
        {
            throw new UserFriendlyException($"You have no verified address on {channel} to hear by; add one first.");
        }

        await using (AsyncServiceScope scope = scopes.CreateAsyncScope())
        {
            INotifyDbContext db = scope.ServiceProvider.GetRequiredService<INotifyDbContext>();
            NotificationSettings? settings = await db.NotificationSettings.FirstOrDefaultAsync(s => s.AccountId == me, ct);
            if (settings is null)
            {
                db.NotificationSettings.Add(settings = new NotificationSettings { AccountId = me });
            }

            (settings.Choices, settings.AutoWatch, settings.OwnChanges, settings.DigestEvery, settings.DigestHour, settings.QuietFrom, settings.QuietTo,
                settings.Channel, settings.UpdatedAt) = (choices, input.AutoWatch, input.OwnChanges, every, hour, quietFrom, quietTo, channel, DateTime.UtcNow);
            await db.SaveChangesAsync(ct);
        }

        wakeup.Signal(); // quiet hours may have ended
        return await SettingsDtoAsync(me, ct);
    }

    /// <summary>The person's notices, newest first (50 a page, before a moment for the next), and how many they haven't read.</summary>
    public async Task<InboxView> InboxAsync(Guid me, bool unreadOnly, DateTime? before, CancellationToken ct)
    {
        List<Notice> found;
        int unread;
        await using (AsyncServiceScope scope = scopes.CreateAsyncScope())
        {
            INotifyDbContext db = scope.ServiceProvider.GetRequiredService<INotifyDbContext>();
            IQueryable<Notice> mine = db.Notices.AsNoTracking().Where(n => n.AccountId == me && n.Delivery != NoticeChoices.Held);
            unread = await mine.CountAsync(n => n.ReadAt == null, ct);
            if (unreadOnly)
            {
                mine = mine.Where(n => n.ReadAt == null);
            }

            if (before is { } b)
            {
                mine = mine.Where(n => n.CreatedAt < b);
            }

            found = await mine.OrderByDescending(n => n.CreatedAt).Take(50).ToListAsync(ct);
        }

        List<Guid> actors = [.. found.Where(n => n.ActorId is not null).Select(n => n.ActorId!.Value).Distinct()];
        IReadOnlyDictionary<Guid, string> names = actors.Count > 0
            ? await services.GetRequiredService<INotifyPeople>().NamesAsync(actors, ct)
            : new Dictionary<Guid, string>();
        return new InboxView([.. found.Select(n => new NoticeView(n.Id, n.Event, n.SubjectKey, n.Reason, n.Delivery, n.Summary, n.ActorId,
            n.ActorId is { } a ? names.GetValueOrDefault(a) : null, n.CreatedAt, n.SentAt, n.ReadAt, n.Link))], unread);
    }

    public async Task<int> UnreadAsync(Guid me, CancellationToken ct)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().Notices
            .CountAsync(n => n.AccountId == me && n.ReadAt == null && n.Delivery != NoticeChoices.Held, ct);
    }

    /// <summary>Marks the person's notices read (these, or all); returns how many are left unread.</summary>
    public async Task<int> MarkReadAsync(Guid me, InboxReadInput input, CancellationToken ct)
    {
        await using (AsyncServiceScope scope = scopes.CreateAsyncScope())
        {
            IQueryable<Notice> mine = scope.ServiceProvider.GetRequiredService<INotifyDbContext>().Notices.Where(n => n.AccountId == me && n.ReadAt == null);
            if (!input.All)
            {
                List<Guid> ids = input.Ids ?? [];
                mine = mine.Where(n => ids.Contains(n.Id));
            }

            await mine.ExecuteUpdateAsync(u => u.SetProperty(n => n.ReadAt, DateTime.UtcNow), ct);
        }

        return await UnreadAsync(me, ct);
    }

    public async Task<int> MarkUnreadAsync(Guid me, Guid id, CancellationToken ct)
    {
        await using (AsyncServiceScope scope = scopes.CreateAsyncScope())
        {
            int changed = await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().Notices.Where(n => n.AccountId == me && n.Id == id)
                .ExecuteUpdateAsync(u => u.SetProperty(n => n.ReadAt, (DateTime?)null), ct);
            if (changed == 0)
            {
                throw new EntityNotFoundException(typeof(Notice), id);
            }
        }

        return await UnreadAsync(me, ct);
    }

    // ----- The site's settings -----

    public async Task<NoticeSiteSettingsDto> SiteAsync(CancellationToken ct)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        NoticeSiteSettings? saved = await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().NoticeSiteSettings.AsNoTracking()
            .FirstOrDefaultAsync(s => s.Id == NoticeSiteSettings.SiteId, ct);
        return saved is null ? new NoticeSiteSettingsDto(options.Value.WindowSeconds, options.Value.MailsPerHour)
            : new NoticeSiteSettingsDto(saved.WindowSeconds, saved.MailsPerHour);
    }

    public async Task<NoticeSiteSettingsDto> SaveSiteAsync(NoticeSiteSettingsDto input, CancellationToken ct)
    {
        if (input.WindowSeconds is < 0 or > 3600)
        {
            throw new UserFriendlyException("Gather a person's notices for 0 to 3,600 seconds after a message.");
        }

        if (input.MailsPerHour is < 1 or > 1000)
        {
            throw new UserFriendlyException("A person gets 1 to 1,000 messages an hour before the rest go to their digest.");
        }

        await using (AsyncServiceScope scope = scopes.CreateAsyncScope())
        {
            INotifyDbContext db = scope.ServiceProvider.GetRequiredService<INotifyDbContext>();
            NoticeSiteSettings? saved = await db.NoticeSiteSettings.FirstOrDefaultAsync(s => s.Id == NoticeSiteSettings.SiteId, ct);
            if (saved is null)
            {
                db.NoticeSiteSettings.Add(saved = new NoticeSiteSettings(NoticeSiteSettings.SiteId));
            }

            (saved.WindowSeconds, saved.MailsPerHour, saved.UpdatedAt) = (input.WindowSeconds, input.MailsPerHour, DateTime.UtcNow);
            await db.SaveChangesAsync(ct);
        }

        wakeup.Signal();
        return await SiteAsync(ct);
    }
}
