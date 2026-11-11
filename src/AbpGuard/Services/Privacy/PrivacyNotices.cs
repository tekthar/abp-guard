using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using AbpGuard.Domain;
using Volo.Abp;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services.Privacy;

/// <summary>A notice's text in one language: Markdown, a link to where it's published, or both.</summary>
public sealed record PrivacyNoticeText(string? Markdown, string? Link);

/// <summary>
/// The notice as anyone reads it: its version, the text in their language (else the site's first), and whom to ask. The
/// Markdown is an admin's and shown to anyone, at /privacy and at sign-up: a host renders it safely, as it does comments
/// (no raw HTML, links http(s) only, as the link itself is checked).
/// </summary>
public sealed record PrivacyNoticeDto(int Version, string Language, string? Markdown, string? Link, DateTime PublishedAt, PrivacyContactDto Officer,
    PrivacyContactDto Controller);

/// <summary>A version as admins see it, with every language's text.</summary>
public sealed record PrivacyNoticeVersionDto(int Version, IReadOnlyDictionary<string, PrivacyNoticeText> Texts, DateTime PublishedAt, Guid? PublishedBy,
    int Accepted);

public sealed record PrivacyNoticeInput(Dictionary<string, PrivacyNoticeText>? Texts);

public sealed record NoticeAcceptInput(int Version);

public sealed record ConsentWithdrawInput(string Store);

public sealed record ConsentHandledInput(string? Note);

/// <summary>A store whose legal basis is consent, and whether the person withdrew theirs.</summary>
public sealed record ConsentStoreDto(string Key, LocalizedText Name, LocalizedText Purpose, DateTime? WithdrawnAt, DateTime? HandledAt);

/// <summary>Where a person stands: the notice now, the one they accepted, and their consent store by store.</summary>
public sealed record MyPrivacyDto(int? CurrentVersion, int? AcceptedVersion, DateTime? AcceptedAt, bool NeedsAcceptance, IReadOnlyList<ConsentStoreDto> Consent);

public sealed record ConsentWithdrawalDto(Guid Id, Guid AccountId, string? Username, string Store, DateTime At, DateTime? HandledAt, string? Note);

/// <summary>
/// The privacy notice and consent (PDPL). A site admin publishes the notice in each language
/// (Markdown, a link, or both); each publish is a new version. Anyone reads it at /privacy; sign-up shows it and records
/// that it was accepted, as a host's own forms do through <see cref="IPrivacyNoticeAcceptance"/> (a portal's request);
/// a person signed in on the web is asked again when the version changes. Where a store's legal basis is consent, a
/// person may withdraw theirs, which an admin then acts on and marks handled.
/// </summary>
[ExposeServices(typeof(PrivacyNotices), typeof(IPrivacyNoticeAcceptance))]
public sealed class PrivacyNotices(GuardDb guardDb, PersonalDataCatalog catalog, IGuardSiteDefaults site, Microsoft.Extensions.Options.IOptions<GuardOptions> options)
    : IPrivacyNoticeAcceptance, ITransientDependency
{
    public const int MarkdownLength = 50_000;
    public const string AcceptCode = "accept_notice";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>The version forms must show and send, or null: none published, or the notice turned off (Guard:Features:PrivacyNotice), so no form can read it.</summary>
    public Task<int?> CurrentVersionAsync(CancellationToken cancellationToken = default) => !options.Value.Features.PrivacyNotice
        ? Task.FromResult<int?>(null)
        : guardDb.RunAsync(db =>
            db.PrivacyNotices.AsNoTracking().OrderByDescending(n => n.Number).Select(n => (int?)n.Number).FirstOrDefaultAsync(cancellationToken),
            cancellationToken: cancellationToken);

    public Task RecordAsync(Guid? accountId, string? address, int version, string where, string? ip, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            db.PrivacyAcceptances.Add(new PrivacyAcceptance(Guid.NewGuid(), accountId, address?.Trim().ToLowerInvariant(), version, where, ip));
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken);

    /// <summary>The version a form shows must be the one now: refuses one older, or none, while a notice is published.</summary>
    public async Task EnsureAcceptedAsync(int? version, CancellationToken ct)
    {
        if (await CurrentVersionAsync(ct) is { } current && version != current)
        {
            throw new UserFriendlyException("Read and accept the privacy notice to go on.", AcceptCode);
        }
    }

    public Task<PrivacyNoticeDto?> CurrentAsync(string? language, CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        PrivacyNoticeVersion? notice = await db.PrivacyNotices.AsNoTracking().OrderByDescending(n => n.Number).FirstOrDefaultAsync(ct);
        if (notice is null)
        {
            return null;
        }

        Dictionary<string, PrivacyNoticeText> texts = TextsOf(notice);
        // The language asked for, else the request's (or its base: "ar" for "ar-SA"), else English, else any.
        string want = (language ?? site.RequestLanguage).ToLowerInvariant();
        string lang = new[] { want, want.Split('-')[0], "en" }.FirstOrDefault(texts.ContainsKey) ?? texts.Keys.Order(StringComparer.Ordinal).First();
        PrivacySettings? settings = await db.PrivacySettings.AsNoTracking().FirstOrDefaultAsync(ct);
        return (PrivacyNoticeDto?)new PrivacyNoticeDto(notice.Number, lang, texts[lang].Markdown, texts[lang].Link, notice.PublishedAt,
            new PrivacyContactDto(settings?.OfficerName, settings?.OfficerContact), new PrivacyContactDto(settings?.ControllerName, settings?.ControllerContact));
    }, cancellationToken: ct);

    public Task<List<PrivacyNoticeVersionDto>> VersionsAsync(CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        List<PrivacyNoticeVersion> notices = await db.PrivacyNotices.AsNoTracking().OrderByDescending(n => n.Number).Take(100).ToListAsync(ct);
        Dictionary<int, int> accepted = await db.PrivacyAcceptances.AsNoTracking().GroupBy(a => a.Version).Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(g => g.Key, g => g.Count, ct);
        return notices.Select(n => new PrivacyNoticeVersionDto(n.Number, TextsOf(n), n.PublishedAt, n.PublishedBy, accepted.GetValueOrDefault(n.Number))).ToList();
    }, cancellationToken: ct);

    public async Task<PrivacyNoticeVersionDto> PublishAsync(PrivacyNoticeInput input, Guid actor, CancellationToken ct)
    {
        Dictionary<string, PrivacyNoticeText> texts = [];
        foreach ((string language, PrivacyNoticeText text) in input.Texts ?? [])
        {
            string? markdown = string.IsNullOrWhiteSpace(text.Markdown) ? null : text.Markdown.Trim();
            string? link = string.IsNullOrWhiteSpace(text.Link) ? null : text.Link.Trim();
            if (markdown is null && link is null)
            {
                continue;
            }

            if (markdown?.Length > MarkdownLength)
            {
                throw new UserFriendlyException($"A notice is at most {MarkdownLength} characters.");
            }

            if (link is not null && (!Uri.TryCreate(link, UriKind.Absolute, out Uri? uri) || uri.Scheme is not ("https" or "http")))
            {
                throw new UserFriendlyException("A notice's link is a web address, starting with https://.");
            }

            texts[language.Trim().ToLowerInvariant()] = new PrivacyNoticeText(markdown, link);
        }

        if (texts.Count == 0)
        {
            throw new UserFriendlyException("Give the notice's text, or a link to it, in at least one language.");
        }

        return await guardDb.RunAsync(async db =>
        {
            PrivacyNoticeVersion notice = db.PrivacyNotices.Add(new PrivacyNoticeVersion { Texts = JsonSerializer.Serialize(texts, Json), PublishedBy = actor }).Entity;
            await db.SaveChangesAsync(ct);
            return new PrivacyNoticeVersionDto(notice.Number, texts, notice.PublishedAt, actor, 0);
        }, requiresNew: true, ct);
    }

    public async Task<MyPrivacyDto> MineAsync(Guid accountId, CancellationToken ct)
    {
        PrivacyMapDto map = await catalog.MapAsync(ct);
        List<PrivacyStoreDto> consent = [.. map.Stores.Where(s => s.Recorded?.LegalBasis == LegalBases.Consent)];
        return await guardDb.RunAsync(async db =>
        {
            int? current = await db.PrivacyNotices.AsNoTracking().OrderByDescending(n => n.Number).Select(n => (int?)n.Number).FirstOrDefaultAsync(ct);
            List<string> addresses = await AddressesAsync(db, accountId, ct);
            PrivacyAcceptance? last = await db.PrivacyAcceptances.AsNoTracking()
                .Where(a => a.AccountId == accountId || (a.Address != null && addresses.Contains(a.Address))).OrderByDescending(a => a.Version).ThenByDescending(a => a.At)
                .FirstOrDefaultAsync(ct);
            Dictionary<string, ConsentWithdrawal> withdrawn = (await db.ConsentWithdrawals.AsNoTracking().Where(w => w.AccountId == accountId).ToListAsync(ct))
                .GroupBy(w => w.StoreKey).ToDictionary(g => g.Key, g => g.OrderByDescending(w => w.At).First());
            return new MyPrivacyDto(current, last?.Version, last?.At, current is { } c && last?.Version != c,
                [.. consent.Select(s => new ConsentStoreDto(s.Key, s.Name, s.Purpose, withdrawn.GetValueOrDefault(s.Key)?.At, withdrawn.GetValueOrDefault(s.Key)?.HandledAt))]);
        }, cancellationToken: ct);
    }

    private static async Task<List<string>> AddressesAsync(Data.GuardDbContext db, Guid accountId, CancellationToken ct)
    {
        string? email = await db.Accounts.AsNoTracking().Where(a => a.Id == accountId).Select(a => a.Email).FirstOrDefaultAsync(ct);
        List<string> added = await db.AccountEmails.AsNoTracking().Where(e => e.AccountId == accountId && e.VerifiedAt != null).Select(e => e.Email).ToListAsync(ct);
        return [.. added.Append(email).OfType<string>().Select(e => e.ToLowerInvariant())];
    }

    public async Task AcceptAsync(Guid accountId, int version, string? ip, CancellationToken ct)
    {
        await EnsureAcceptedAsync(version, ct);
        await RecordAsync(accountId, null, version, NoticeAcceptedWhere.SignIn, ip, ct);
    }

    public async Task<ConsentWithdrawalDto> WithdrawAsync(Guid accountId, string store, CancellationToken ct)
    {
        PrivacyMapDto map = await catalog.MapAsync(ct);
        if (!map.Stores.Any(s => s.Key == store && s.Recorded?.LegalBasis == LegalBases.Consent))
        {
            throw new UserFriendlyException("Consent can be withdrawn only where the site keeps data on consent.");
        }

        return await guardDb.RunAsync(async db =>
        {
            ConsentWithdrawal withdrawal = await db.ConsentWithdrawals.FirstOrDefaultAsync(w => w.AccountId == accountId && w.StoreKey == store && w.HandledAt == null, ct)
                ?? db.ConsentWithdrawals.Add(new ConsentWithdrawal(Guid.NewGuid(), accountId, store)).Entity;
            await db.SaveChangesAsync(ct);
            return Dto(withdrawal, null);
        }, requiresNew: true, ct);
    }

    public Task<List<ConsentWithdrawalDto>> WithdrawalsAsync(CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        List<ConsentWithdrawal> rows = await db.ConsentWithdrawals.AsNoTracking().OrderBy(w => w.HandledAt != null).ThenByDescending(w => w.At).Take(500).ToListAsync(ct);
        List<Guid> ids = [.. rows.Select(r => r.AccountId)];
        Dictionary<Guid, string> names = await db.Accounts.AsNoTracking().Where(a => ids.Contains(a.Id)).ToDictionaryAsync(a => a.Id, a => a.Username, ct);
        return rows.Select(r => Dto(r, names.GetValueOrDefault(r.AccountId))).ToList();
    }, cancellationToken: ct);

    public Task<ConsentWithdrawalDto> HandleAsync(Guid id, Guid actor, string? note, CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        ConsentWithdrawal withdrawal = await db.ConsentWithdrawals.FirstOrDefaultAsync(w => w.Id == id, ct)
            ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(ConsentWithdrawal), id);
        (withdrawal.HandledAt, withdrawal.HandledBy, withdrawal.Note) = (withdrawal.HandledAt ?? DateTime.UtcNow, actor, string.IsNullOrWhiteSpace(note) ? null : note.Trim()[..Math.Min(note.Trim().Length, 2000)]);
        await db.SaveChangesAsync(ct);
        return Dto(withdrawal, null);
    }, requiresNew: true, ct);

    private static ConsentWithdrawalDto Dto(ConsentWithdrawal w, string? username) => new(w.Id, w.AccountId, username, w.StoreKey, w.At, w.HandledAt, w.Note);

    private static Dictionary<string, PrivacyNoticeText> TextsOf(PrivacyNoticeVersion notice) =>
        JsonSerializer.Deserialize<Dictionary<string, PrivacyNoticeText>>(notice.Texts, Json) ?? [];
}
