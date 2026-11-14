using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using AbpGuard.Domain;
using Volo.Abp;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

public sealed record SecurityFeedDto(string? Url, bool Enabled, bool HasSecret, DateTime? LastSentAt, string? LastError, DateTime? FailingSince);

public sealed record SecurityFeedInput(string? Url, bool Enabled);

/// <summary>A new secret, shown once: the receiver checks each batch's signature with it.</summary>
public sealed record SecurityFeedSecretDto(string Secret);

/// <summary>
/// The security log as a feed (PDPL): a site admin sets an address (a SIEM's, a log store's), and each
/// minute the events since the last batch go there as a JSON array, oldest first, signed with the site's secret:
/// <c>X-Guard-Signature: t={unix seconds},v1={hex HMAC-SHA256 of "t.body"}</c> (the header's name is the host's,
/// GuardNames.FeedSignatureHeader, and the same value goes under each of GuardNames.FormerFeedSignatureHeaders). The
/// secret is kept protected (Data Protection) and shown once when made. A batch
/// that doesn't arrive is sent again until it does; the page says since when it fails.
/// </summary>
public sealed class SecurityFeed(GuardDb guardDb, IDataProtectionProvider protection, IOptions<GuardNames> names, ISecurityFeedSender sender,
    ILogger<SecurityFeed> logger) : ITransientDependency
{
    public const int Batch = 500;

    /// <summary>The signature's header unless the host names another (GuardNames.FeedSignatureHeader).</summary>
    public const string SignatureHeader = "X-Guard-Signature";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private IDataProtector Protector => protection.CreateProtector(names.Value.Purpose("SecurityFeed.v1"));

    public Task<SecurityFeedDto> GetAsync(CancellationToken ct) => guardDb.RunAsync(async db =>
        Dto(await db.SecurityFeeds.AsNoTracking().FirstOrDefaultAsync(ct)), cancellationToken: ct);

    public async Task<SecurityFeedDto> SaveAsync(SecurityFeedInput input, CancellationToken ct)
    {
        string? url = string.IsNullOrWhiteSpace(input.Url) ? null : input.Url.Trim();
        // https, but for a receiver on the server's own machine (a collector beside it, a test's).
        if (url is not null && (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri) || !(uri.Scheme == Uri.UriSchemeHttps || uri is { Scheme: "http", IsLoopback: true })))
        {
            throw new UserFriendlyException("The feed's address starts with https://: the log goes nowhere in the clear.");
        }

        if (input.Enabled && url is null)
        {
            throw new UserFriendlyException("Give the feed's address before turning it on.");
        }

        return await guardDb.RunAsync(async db =>
        {
            SecurityFeedSettings feed = await LoadAsync(db, ct);
            if (feed.Url != url)
            {
                // A new receiver starts from now, not with the whole log.
                (feed.CursorTime, feed.CursorId, feed.LastError, feed.FailingSince) = (DateTime.UtcNow, null, null, null);
            }

            (feed.Url, feed.Enabled) = (url, input.Enabled);
            if (feed.Enabled && feed.ProtectedSecret is null)
            {
                throw new UserFriendlyException("Make the feed's secret first, and give it to the receiver.", "no_secret");
            }

            await db.SaveChangesAsync(ct);
            return Dto(feed);
        }, requiresNew: true, ct);
    }

    public Task<SecurityFeedSecretDto> NewSecretAsync(CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        SecurityFeedSettings feed = await LoadAsync(db, ct);
        string secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        feed.ProtectedSecret = Protector.Protect(secret);
        await db.SaveChangesAsync(ct);
        return new SecurityFeedSecretDto(secret);
    }, requiresNew: true, ct);

    /// <summary>Sends what's new, batch after batch; returns how many events went. Nothing when the feed is off.</summary>
    public async Task<int> SendAsync(CancellationToken ct)
    {
        int sent = 0;
        while (true)
        {
            (SecurityFeedSettings? feed, List<SecurityEvent> events) = await guardDb.RunAsync(async db =>
            {
                SecurityFeedSettings? f = await db.SecurityFeeds.AsNoTracking().FirstOrDefaultAsync(ct);
                if (f is not { Enabled: true, Url: not null, ProtectedSecret: not null })
                {
                    return ((SecurityFeedSettings?)null, new List<SecurityEvent>());
                }

                // After the last event sent: by time, and among events of that very time by id (the few sharing it are read again and dropped).
                DateTime from = f.CursorTime ?? DateTime.MinValue;
                Guid after = f.CursorId ?? Guid.Empty;
                List<SecurityEvent> next = [.. (await db.SecurityEvents.AsNoTracking().Where(e => e.Time >= from).OrderBy(e => e.Time).ThenBy(e => e.Id)
                        .Take(Batch + 100).ToListAsync(ct))
                    .Where(e => e.Time > from || string.CompareOrdinal(e.Id.ToString(), after.ToString()) > 0).Take(Batch)]; // uuids order as their text
                return ((SecurityFeedSettings?)f, next);
            }, cancellationToken: ct);
            if (feed is null || events.Count == 0)
            {
                return sent;
            }

            byte[] body = JsonSerializer.SerializeToUtf8Bytes(events.Select(e => new
            {
                id = e.Id, time = e.Time, type = e.Type, username = e.Username, accountId = e.AccountId, actingAccountId = e.ActingAccountId, actingMode = e.ActingMode,
                targetType = e.TargetType, targetId = e.TargetId, targetName = e.TargetName, detail = e.Detail, ip = e.Ip,
            }), Json);
            SecurityFeedResult result = await sender.SendAsync(new Uri(feed.Url!), body, Sign(Protector.Unprotect(feed.ProtectedSecret!), body, header: names.Value.FeedSignatureHeader, alsoUnder: names.Value.FormerFeedSignatureHeaders), ct);
            await guardDb.RunAsync(async db =>
            {
                SecurityFeedSettings f = await LoadAsync(db, ct);
                if (result.Delivered)
                {
                    (f.CursorTime, f.CursorId, f.LastSentAt, f.LastError, f.FailingSince) = (events[^1].Time, events[^1].Id, DateTime.UtcNow, null, null);
                }
                else
                {
                    (f.LastError, f.FailingSince) = (result.Error, f.FailingSince ?? DateTime.UtcNow);
                }

                await db.SaveChangesAsync(ct);
            }, requiresNew: true, ct);
            if (!result.Delivered)
            {
                logger.LogWarning("The security log's feed didn't arrive: {Error}", result.Error);
                return sent;
            }

            sent += events.Count;
            if (events.Count < Batch)
            {
                return sent;
            }
        }
    }

    /// <summary>
    /// The signature headers of a body, for a secret: what a receiver computes to know it's the site's. The same value
    /// goes under <paramref name="header"/> and each of <paramref name="alsoUnder"/> (a host's former names).
    /// </summary>
    public static Dictionary<string, string> Sign(string secret, byte[] body, DateTimeOffset? at = null, string header = SignatureHeader,
        IEnumerable<string>? alsoUnder = null)
    {
        string t = (at ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        byte[] signed = [.. Encoding.UTF8.GetBytes(t + "."), .. body];
        string v1 = Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), signed));
        Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase) { [header] = $"t={t},v1={v1}" };
        foreach (string former in alsoUnder ?? [])
        {
            if (!string.IsNullOrWhiteSpace(former))
            {
                headers.TryAdd(former.Trim(), headers[header]);
            }
        }

        return headers;
    }

    private static async Task<SecurityFeedSettings> LoadAsync(Data.GuardDbContext db, CancellationToken ct) =>
        await db.SecurityFeeds.FirstOrDefaultAsync(ct) ?? db.SecurityFeeds.Add(new SecurityFeedSettings { CursorTime = DateTime.UtcNow }).Entity;

    private static SecurityFeedDto Dto(SecurityFeedSettings? f) =>
        new(f?.Url, f?.Enabled ?? false, f?.ProtectedSecret is not null, f?.LastSentAt, f?.LastError, f?.FailingSince);
}

/// <summary>Sends the feed each minute, on one server at a time.</summary>
public sealed class SecurityFeedWorker(IServiceScopeFactory scopes, IGuardLocks locks, IOptions<GuardOptions> options, ILogger<SecurityFeedWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using PeriodicTimer timer = new(TimeSpan.FromMinutes(1));
        while (options.Value.Features.SecurityFeed && await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await using IAsyncDisposable? held = await locks.TryTakeAsync("security-feed", stoppingToken);
                if (held is not null)
                {
                    await using AsyncServiceScope scope = scopes.CreateAsyncScope();
                    await scope.ServiceProvider.GetRequiredService<SecurityFeed>().SendAsync(stoppingToken);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Sending the security log's feed failed; it tries again in a minute.");
            }
        }
    }
}
