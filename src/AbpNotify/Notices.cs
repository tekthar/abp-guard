using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata;
using Volo.Abp;
using Volo.Abp.Domain.Entities;
using Volo.Abp.EntityFrameworkCore;

namespace AbpNotify;

// The notices' tables, in the application's own context. The application keeps which events become notices, how they
// read, its mail, and who may manage teams' channels.

/// <summary>How a person hears of an event: now, in a digest, or not at all.</summary>
public static class NoticeChoices
{
    public const string Now = "now";
    public const string Digest = "digest";
    public const string Off = "off";

    /// <summary>
    /// Not a person's choice: a bulk change's notice, held while it gathers what it's about and released as one when
    /// the change ends. Neither sent nor in the inbox while held.
    /// </summary>
    public const string Held = "held";

    /// <summary>
    /// Not a person's choice either: told already by a message of its own, and kept for the inbox only. Never sent
    /// again, nor gathered in a digest.
    /// </summary>
    public const string Told = "told";

    public static readonly IReadOnlyList<string> All = [Now, Digest, Off];
}

/// <summary>How often a person's digest comes: every hour, or once a day at their hour.</summary>
public static class DigestFrequencies
{
    public const string Hourly = "hourly";
    public const string Daily = "daily";

    public static readonly IReadOnlyList<string> All = [Hourly, Daily];
}

/// <summary>The phones a person's app may run on.</summary>
public static class DevicePlatforms
{
    public const string Android = "android";
    public const string Ios = "ios";

    public static readonly IReadOnlyList<string> All = [Android, Ios];
}

/// <summary>
/// A person's own choices: how they hear of each event, whether what they do starts them watching something, whether
/// they hear of their own changes, the channel what's told now goes by, when their digest comes, and their quiet hours.
/// </summary>
public class NotificationSettings
{
    public Guid AccountId { get; set; }

    /// <summary>Event → choice; an event not named is <see cref="NoticeChoices.Now"/>.</summary>
    public Dictionary<string, string> Choices { get; set; } = [];

    public bool AutoWatch { get; set; } = true;
    public bool OwnChanges { get; set; }

    public string DigestEvery { get; set; } = DigestFrequencies.Daily;

    /// <summary>The channel what's told now goes by: email, or one that reaches them (Slack, SMS); digests always come by email.</summary>
    public string Channel { get; set; } = "email";

    /// <summary>The hour (0–23, their time zone) a daily digest comes.</summary>
    public int DigestHour { get; set; } = 8;

    /// <summary>Quiet hours, as minutes after midnight in their time zone: nothing is sent from the first to the second (it may span midnight).</summary>
    public int? QuietFrom { get; set; }

    public int? QuietTo { get; set; }
    public DateTime? LastDigestAt { get; set; }
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public string ChoiceFor(string @event) => Choices.GetValueOrDefault(@event) is { } c && NoticeChoices.All.Contains(c) ? c : NoticeChoices.Now;

    /// <summary>Whether a moment falls in their quiet hours, in their time zone.</summary>
    public bool Quiet(DateTime utc, TimeZoneInfo zone)
    {
        if (QuietFrom is not { } from || QuietTo is not { } to || from == to)
        {
            return false;
        }

        DateTime local = TimeZoneInfo.ConvertTimeFromUtc(utc, zone);
        int minute = local.Hour * 60 + local.Minute;
        return from < to ? minute >= from && minute < to : minute >= from || minute < to;
    }

    /// <summary>Whether their digest is due: hourly, an hour after the last; daily, once their hour has come today and it hasn't gone since.</summary>
    public bool DigestDue(DateTime utc, TimeZoneInfo zone)
    {
        if (DigestEvery == DigestFrequencies.Hourly)
        {
            return LastDigestAt is not { } last || utc - last >= TimeSpan.FromHours(1);
        }

        DateTime local = TimeZoneInfo.ConvertTimeFromUtc(utc, zone);
        DateTime todays = TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(local.Date.AddHours(DigestHour), DateTimeKind.Unspecified), zone);
        return utc >= todays && (LastDigestAt is not { } sent || sent < todays);
    }

    public static string? Clock(int? minutes) => minutes is { } m ? $"{m / 60:00}:{m % 60:00}" : null;

    /// <summary>"HH:mm" as minutes after midnight; null for none.</summary>
    public static int? Minutes(string? clock)
    {
        if (string.IsNullOrWhiteSpace(clock))
        {
            return null;
        }

        return TimeOnly.TryParseExact(clock.Trim(), "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out TimeOnly t)
            ? t.Hour * 60 + t.Minute
            : throw new UserFriendlyException($"\"{clock}\" isn't a time of day (HH:mm).");
    }
}

/// <summary>The site's settings for sending notices (one row); none until an admin saves them, and the configured defaults stand.</summary>
public class NoticeSiteSettings : Entity<Guid>
{
    public static readonly Guid SiteId = Guid.Parse("00000000-0000-0000-0000-0000000000a2");

    protected NoticeSiteSettings()
    {
    }

    public NoticeSiteSettings(Guid id) : base(id)
    {
    }

    public int WindowSeconds { get; set; }
    public int MailsPerHour { get; set; }
    public DateTime UpdatedAt { get; set; }
}

/// <summary>
/// One person told of one event: sent now, or kept for their digest. Unique per event and person, so an event heard
/// twice tells once. It may be about something (a subject, with its key, in a scope of the application's), or nothing
/// in particular. It carries its own message (a template and its model) for the sender, and the inbox reads it.
/// </summary>
public class Notice : Entity<Guid>
{
    protected Notice()
    {
    }

    public Notice(Guid id, Guid eventId, Guid accountId, string @event, string reason, Guid? actorId, string delivery, string summary,
        Guid? scopeId = null, Guid? subjectId = null, string? subjectKey = null) : base(id)
    {
        EventId = eventId;
        AccountId = accountId;
        Event = @event;
        Reason = reason;
        ActorId = actorId;
        Delivery = delivery;
        Summary = summary.Length > 500 ? summary[..500] : summary;
        ScopeId = scopeId;
        SubjectId = subjectId;
        SubjectKey = subjectKey;
        CreatedAt = DateTime.UtcNow;
    }

    public Guid EventId { get; private set; }
    public Guid AccountId { get; private set; }
    public string Event { get; private set; } = "";

    /// <summary>Why they heard: what reached them ("watchers", "assignee", "group", "role", "mentioned").</summary>
    public string Reason { get; private set; } = "";

    public Guid? ActorId { get; private set; }

    /// <summary><see cref="NoticeChoices.Now"/>, <see cref="NoticeChoices.Digest"/>, held or told.</summary>
    public string Delivery { get; set; } = NoticeChoices.Now;

    /// <summary>What happened, in a line, in English (its message says it in their language).</summary>
    public string Summary { get; private set; } = "";

    /// <summary>The application's scope it's in (a project), when it has one.</summary>
    public Guid? ScopeId { get; private set; }

    /// <summary>What it's about, and that thing's key (a record's), when it's about one.</summary>
    public Guid? SubjectId { get; private set; }

    public string? SubjectKey { get; private set; }

    /// <summary>Where it leads in the app (a path), when it isn't about a subject.</summary>
    public string? Link { get; init; }

    /// <summary>The template its own message uses, and the model (JSON) it's rendered with.</summary>
    public string? Template { get; init; }

    public string? ModelJson { get; init; }

    /// <summary>What sent it, for the message log.</summary>
    public string? Source { get; init; }

    /// <summary>Sent at once and on its own, never gathered with others (a mention is meant for the person); quiet hours and the hourly cap still hold.</summary>
    public bool Alone { get; init; }

    public DateTime CreatedAt { get; private set; }

    /// <summary>The message it went in (one may carry several), claimed before it's sent.</summary>
    public Guid? MailId { get; set; }

    public DateTime? SentAt { get; set; }
    public DateTime? ReadAt { get; set; }

    /// <summary>A model as a notice keeps it: JSON, so it renders the same whenever its message goes.</summary>
    public static string Keep(IReadOnlyDictionary<string, object?> model) => JsonSerializer.Serialize(model);

    /// <summary>A kept model back as plain values (dictionaries, lists, strings, numbers, booleans) for a template engine.</summary>
    public static Dictionary<string, object?> Model(string? json) =>
        json is { Length: > 0 } && Plain(JsonSerializer.Deserialize<JsonElement>(json)) is Dictionary<string, object?> model ? model : [];

    private static object? Plain(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Object => e.EnumerateObject().ToDictionary(p => p.Name, p => Plain(p.Value)),
        JsonValueKind.Array => e.EnumerateArray().Select(Plain).ToList(),
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Number => e.TryGetInt64(out long l) ? l : e.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => null,
    };
}

/// <summary>
/// A person's address on a channel other than email: a phone number for SMS, a chat member. Only a verified one is
/// used; one people type is verified with a code the channel sends to it first.
/// </summary>
public class ChannelAddress
{
    public Guid AccountId { get; set; }
    public string Channel { get; set; } = "";
    public string Address { get; set; } = "";
    public DateTime? VerifiedAt { get; set; }

    /// <summary>The code waiting to be typed back (hashed), until when, and how many wrong tries there were.</summary>
    public string? CodeHash { get; set; }

    public DateTime? CodeExpiresAt { get; set; }
    public int CodeTries { get; set; }
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// A team's channel to post to: a Slack channel or a Teams channel, through a connection, at site scope or one of the
/// application's scopes (a project).
/// </summary>
public class ChannelTarget : Entity<Guid>
{
    protected ChannelTarget()
    {
    }

    public ChannelTarget(Guid id, Guid? scopeId, string name, string channel, Guid connectionId, string where, Guid createdBy) : base(id)
    {
        ScopeId = scopeId;
        Name = name;
        Channel = channel;
        ConnectionId = connectionId;
        Where = where;
        CreatedBy = createdBy;
        CreatedAt = DateTime.UtcNow;
    }

    public Guid? ScopeId { get; private set; }
    public string Name { get; set; } = "";

    /// <summary>The channel's key: <c>slack</c> or <c>teams</c>.</summary>
    public string Channel { get; private set; } = "";

    public Guid ConnectionId { get; private set; }

    /// <summary>Slack's channel (its id or name); empty for Teams, whose webhook is the channel.</summary>
    public string Where { get; set; } = "";

    public Guid CreatedBy { get; private set; }
    public DateTime CreatedAt { get; private set; }
}

/// <summary>That an event was posted to a team's channel: an event heard twice posts once.</summary>
public class ChannelPost
{
    public Guid EventId { get; set; }
    public Guid TargetId { get; set; }
    public DateTime PostedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// A phone a person signed in to the application's app on: its push token from Firebase, which reaches that one app
/// on that one phone. A token is one phone's, so it belongs to whoever signed in there last.
/// </summary>
public class PersonDevice : Entity<Guid>
{
    public const int MaxToken = 1024;
    public const int MaxName = 100;

    protected PersonDevice()
    {
    }

    public PersonDevice(Guid id, Guid accountId, string token, string platform, string name) : base(id)
    {
        AccountId = accountId;
        Token = token;
        Platform = platform;
        Name = name;
        CreatedAt = LastSeenAt = DateTime.UtcNow;
    }

    public Guid AccountId { get; set; }

    /// <summary>The phone's FCM registration token; never shown, not even to the person.</summary>
    public string Token { get; private set; } = "";

    /// <summary><see cref="DevicePlatforms.Android"/> or <see cref="DevicePlatforms.Ios"/>.</summary>
    public string Platform { get; set; } = "";

    /// <summary>What the phone calls itself ("Pixel 8"), so the person knows which is which.</summary>
    public string Name { get; set; } = "";

    public DateTime CreatedAt { get; private set; }

    /// <summary>When the app last said it's there (it does on every start, and when its token changes).</summary>
    public DateTime LastSeenAt { get; set; }
}

/// <summary>
/// The notices' tables, in the application's own context: the context implements this, maps them with
/// <see cref="NotifyModel.ConfigureNotify"/>, and stands in for it (<c>ReplaceDbContext</c>).
/// </summary>
public interface INotifyDbContext : IEfCoreDbContext
{
    DbSet<Notice> Notices { get; }

    DbSet<NotificationSettings> NotificationSettings { get; }

    DbSet<NoticeSiteSettings> NoticeSiteSettings { get; }

    DbSet<ChannelAddress> ChannelAddresses { get; }

    DbSet<ChannelTarget> ChannelTargets { get; }

    DbSet<ChannelPost> ChannelPosts { get; }

    DbSet<PersonDevice> Devices { get; }
}

/// <summary>The columns a table made before keeps under its own names: what a notice or a team's channel is in, and what a notice is about.</summary>
public sealed record NotifyColumns(string Scope = "ScopeId", string SubjectId = "SubjectId", string SubjectKey = "SubjectKey");

public static class NotifyModel
{
    /// <summary>
    /// Maps <c>notices</c>, <c>notification_settings</c>, <c>notice_site_settings</c>, <c>channel_addresses</c>,
    /// <c>channel_targets</c>, <c>channel_posts</c> and <c>devices</c> in <paramref name="schema"/> (the context's
    /// default when null), with <paramref name="columns"/> naming the columns a table made before keeps.
    /// </summary>
    public static ModelBuilder ConfigureNotify(this ModelBuilder builder, string? schema = null, NotifyColumns? columns = null)
    {
        columns ??= new NotifyColumns();
        builder.Entity<Notice>(b =>
        {
            b.ToTable("notices", schema);
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.Event).HasMaxLength(32).IsRequired();
            b.Property(x => x.Reason).HasMaxLength(32).IsRequired();
            b.Property(x => x.Delivery).HasMaxLength(16).IsRequired();
            b.Property(x => x.Summary).HasMaxLength(500).IsRequired();
            b.Property(x => x.ScopeId).HasColumnName(columns.Scope);
            b.Property(x => x.SubjectId).HasColumnName(columns.SubjectId);
            b.Property(x => x.SubjectKey).HasColumnName(columns.SubjectKey).HasMaxLength(64);
            b.Property(x => x.Link).HasMaxLength(300);
            b.Property(x => x.Template).HasMaxLength(100);
            b.Property(x => x.ModelJson).HasColumnType("jsonb");
            b.Property(x => x.Source).HasMaxLength(100);
            b.HasIndex(x => new { x.EventId, x.AccountId }).IsUnique();
            // What the sender looks at each round: notices not yet sent.
            b.HasIndex(x => x.AccountId).HasFilter("\"SentAt\" IS NULL").HasDatabaseName("IX_notices_waiting");
            b.HasIndex(x => x.MailId);
            b.HasIndex(x => new { x.AccountId, x.CreatedAt });
            b.HasIndex(x => x.SubjectId);
        });
        builder.Entity<NotificationSettings>(b =>
        {
            b.ToTable("notification_settings", schema);
            b.HasKey(x => x.AccountId);
            b.Property(x => x.DigestEvery).HasMaxLength(16).IsRequired();
            b.Property(x => x.Channel).HasMaxLength(200).IsRequired();
            JsonSerializerOptions json = new(JsonSerializerDefaults.Web);
            b.Property(x => x.Choices).HasColumnType("jsonb").HasConversion(
                v => JsonSerializer.Serialize(v, json),
                v => JsonSerializer.Deserialize<Dictionary<string, string>>(v, json) ?? new Dictionary<string, string>(),
                new ValueComparer<Dictionary<string, string>>(
                    (a, c) => JsonSerializer.Serialize(a, json) == JsonSerializer.Serialize(c, json),
                    v => JsonSerializer.Serialize(v, json).GetHashCode(),
                    v => new Dictionary<string, string>(v)));
        });

        // People's addresses on channels, teams' channels to post to, and what was posted.
        builder.Entity<ChannelAddress>(b =>
        {
            b.ToTable("channel_addresses", schema);
            b.HasKey(x => new { x.AccountId, x.Channel });
            b.Property(x => x.Channel).HasMaxLength(200);
            b.Property(x => x.Address).HasMaxLength(200).IsRequired();
            b.Property(x => x.CodeHash).HasMaxLength(64);
        });
        builder.Entity<ChannelTarget>(b =>
        {
            b.ToTable("channel_targets", schema);
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.ScopeId).HasColumnName(columns.Scope);
            b.Property(x => x.Name).HasMaxLength(100).IsRequired();
            b.Property(x => x.Channel).HasMaxLength(200).IsRequired();
            b.Property(x => x.Where).HasMaxLength(100).IsRequired();
            b.HasIndex(x => x.ScopeId);
        });
        builder.Entity<ChannelPost>(b =>
        {
            b.ToTable("channel_posts", schema);
            b.HasKey(x => new { x.EventId, x.TargetId });
            b.HasIndex(x => x.PostedAt);
        });

        // People's phones: a push token is one phone's, so it's unique.
        builder.Entity<PersonDevice>(b =>
        {
            b.ToTable("devices", schema);
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.Token).HasMaxLength(PersonDevice.MaxToken).IsRequired();
            b.Property(x => x.Platform).HasMaxLength(16).IsRequired();
            b.Property(x => x.Name).HasMaxLength(PersonDevice.MaxName).IsRequired();
            b.HasIndex(x => x.Token).IsUnique();
            b.HasIndex(x => x.AccountId);
        });

        builder.Entity<NoticeSiteSettings>(b =>
        {
            b.ToTable("notice_site_settings", schema);
            b.Property(x => x.Id).ValueGeneratedNever();
        });
        return builder;
    }
}

/// <summary>
/// A table's and its columns' names as the application's model maps them, quoted for SQL: the few statements EF can't
/// say (an insert that does nothing on a conflict, a change inside a JSON value) name no table of their own.
/// </summary>
public sealed class NotifyTable
{
    private readonly IEntityType _entity;
    private readonly StoreObjectIdentifier _store;

    private NotifyTable(IEntityType entity)
    {
        _entity = entity;
        _store = StoreObjectIdentifier.Table(entity.GetTableName()!, entity.GetSchema());
        Name = entity.GetSchema() is { } schema ? $"{Quote(schema)}.{Quote(entity.GetTableName()!)}" : Quote(entity.GetTableName()!);
    }

    /// <summary>The table, schema and all.</summary>
    public string Name { get; }

    /// <summary>The table as the context that holds the notices maps it.</summary>
    public static NotifyTable Of<T>(INotifyDbContext db) =>
        Of<T>(db is DbContext context ? context.Model : throw new InvalidOperationException("The notices' tables are in an EF Core context."));

    public static NotifyTable Of<T>(IModel model) =>
        new(model.FindEntityType(typeof(T)) ?? throw new InvalidOperationException($"{typeof(T).Name} isn't mapped: call ConfigureNotify in the context's model."));

    /// <summary>The column a property is kept in.</summary>
    public string this[string property] =>
        Quote(_entity.FindProperty(property)?.GetColumnName(_store) ?? throw new InvalidOperationException($"{_entity.ClrType.Name} has no property {property}."));

    /// <summary>The columns of these properties, in order, comma separated.</summary>
    public string Columns(params string[] properties) => string.Join(", ", properties.Select(p => this[p]));

    private static string Quote(string name) => $"\"{name.Replace("\"", "\"\"")}\"";
}
