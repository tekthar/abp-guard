using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using AbpGuard.Domain;
using Volo.Abp;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services.Privacy;

/// <summary>A retention rule as a site has it: its module or plugin, the default and bounds, the period set, its last sweep.</summary>
public sealed record RetentionRuleDto(string Key, string Store, string Owner, LocalizedText Name, int DefaultDays, int MinDays, int MaxDays, int Days,
    bool IsDefault, DateTime? LastSweptAt, int LastCount);

public sealed record RetentionDto(DateTime? ConfirmedAt, bool ConfirmedByDefault, IReadOnlyList<RetentionRuleDto> Rules);

/// <summary>Periods by rule key (absent: unchanged; null: back to the default), and whether this confirms them.</summary>
public sealed record RetentionInput(Dictionary<string, int?>? Days, bool Confirm);

/// <summary>
/// How long a site keeps what its stores hold about people (PDPL). Each module and plugin gives its rules
/// (<see cref="IPersonalDataSweeper"/>); an admin sets their periods in Administration › Privacy and confirms them once.
/// A new site starts confirmed with the defaults; an upgraded one sweeps nothing until an admin confirms, as removing
/// what a site has kept until now is a decision. A sweep goes rule by rule, in batches, under the cluster's lock, and
/// the security log says how many rows each removed.
/// </summary>
public sealed class PersonalDataRetention(IGuardExtensions extensions, IServiceProvider services, GuardDb guardDb, IGuardLocks locks, SecurityLog audit,
    ILogger<PersonalDataRetention> logger) : ITransientDependency
{
    public const int Batch = 1000;
    public const string LockName = "privacy-retention";

    /// <summary>
    /// The longest key a plugin's rule may have: with an app ID (at most 129) and the dot, its period's key fits the
    /// column's 200.
    /// </summary>
    public const int MaxRuleKeyLength = 64;

    private sealed record Found(RetentionRule Rule, string Key, string Store, string Owner, string? Plugin);

    /// <summary>Every rule of the host's modules (from DI) and of its plugins (each under a lease, its keys prefixed).</summary>
    private async Task<List<Found>> RulesFoundAsync()
    {
        List<Found> found = [.. services.GetServices<IPersonalDataSweeper>().SelectMany(s => s.Rules
            .Select(r => new Found(r, r.Key, r.Store, r.Store.Split('.')[0], null)))];
        await using IGuardLease<IPersonalDataSweeper> lease = extensions.Lease<IPersonalDataSweeper>(services);
        foreach ((string? plugin, IPersonalDataSweeper sweeper) in lease.Items.Where(i => i.PluginKey is not null))
        {
            found.AddRange(PluginRules(plugin!, sweeper).Select(r => new Found(r, $"{plugin}.{r.Key}", $"{plugin}.{r.Store}", plugin!, plugin)));
        }

        return found;
    }

    /// <summary>A plugin's rules, but a key longer than <see cref="MaxRuleKeyLength"/>, which is left out and logged.</summary>
    private IEnumerable<RetentionRule> PluginRules(string plugin, IPersonalDataSweeper sweeper) => sweeper.Rules.Where(rule =>
    {
        if (rule.Key.Length <= MaxRuleKeyLength)
        {
            return true;
        }

        logger.LogWarning("The plugin {Plugin}'s retention rule {Rule} is left out: a rule's key is at most {Max} characters.", plugin, rule.Key, MaxRuleKeyLength);
        return false;
    });

    public async Task<RetentionDto> GetAsync(CancellationToken ct)
    {
        List<Found> rules = await RulesFoundAsync();
        return await guardDb.RunAsync(async db =>
        {
            RetentionSettings? settings = await db.RetentionSettings.AsNoTracking().FirstOrDefaultAsync(ct);
            Dictionary<string, RetentionPeriod> periods = await db.RetentionPeriods.AsNoTracking().ToDictionaryAsync(p => p.RuleKey, ct);
            return new RetentionDto(settings?.ConfirmedAt, settings is { ConfirmedAt: not null, ConfirmedBy: null },
                [.. rules.OrderBy(r => r.Key, StringComparer.Ordinal).Select(r =>
                {
                    RetentionPeriod? period = periods.GetValueOrDefault(r.Key);
                    return new RetentionRuleDto(r.Key, r.Store, r.Owner, r.Rule.Name, r.Rule.DefaultDays, r.Rule.MinDays, r.Rule.MaxDays,
                        DaysOf(r.Rule, period), period?.Days is null, period?.LastSweptAt, period?.LastCount ?? 0);
                })]);
        }, cancellationToken: ct);
    }

    private static int DaysOf(RetentionRule rule, RetentionPeriod? period) => Math.Clamp(period?.Days ?? rule.DefaultDays, rule.MinDays, rule.MaxDays);

    public async Task<RetentionDto> SaveAsync(RetentionInput input, Guid actor, CancellationToken ct)
    {
        Dictionary<string, Found> rules = (await RulesFoundAsync()).ToDictionary(r => r.Key, StringComparer.Ordinal);
        foreach ((string key, int? days) in input.Days ?? [])
        {
            if (!rules.TryGetValue(key, out Found? rule))
            {
                throw new UserFriendlyException($"There's no retention rule '{key}'.");
            }

            if (days is { } d && (d < rule.Rule.MinDays || d > rule.Rule.MaxDays))
            {
                throw new UserFriendlyException($"Keep it from {rule.Rule.MinDays} to {rule.Rule.MaxDays} days.");
            }
        }

        await guardDb.RunAsync(async db =>
        {
            DateTime now = DateTime.UtcNow;
            foreach ((string key, int? days) in input.Days ?? [])
            {
                RetentionPeriod period = await db.RetentionPeriods.FirstOrDefaultAsync(p => p.RuleKey == key, ct)
                    ?? db.RetentionPeriods.Add(new RetentionPeriod { RuleKey = key }).Entity;
                (period.Days, period.UpdatedAt, period.UpdatedBy) = (days, now, actor);
            }

            if (input.Confirm)
            {
                RetentionSettings settings = await db.RetentionSettings.FirstOrDefaultAsync(ct) ?? db.RetentionSettings.Add(new RetentionSettings()).Entity;
                (settings.ConfirmedAt, settings.ConfirmedBy) = (now, actor);
            }

            await db.SaveChangesAsync(ct);
        }, requiresNew: true, ct);
        return await GetAsync(ct);
    }

    /// <summary>
    /// Sweeps every rule with its period: by the daily worker (skipping when another server holds the lock), or an admin
    /// (waiting its turn). Nothing until the periods are confirmed. Returns how many rows each rule removed, or null.
    /// </summary>
    public async Task<Dictionary<string, int>?> SweepAsync(bool wait, CancellationToken ct)
    {
        bool confirmed = await guardDb.RunAsync(db => db.RetentionSettings.AnyAsync(s => s.ConfirmedAt != null, ct), cancellationToken: ct);
        if (!confirmed)
        {
            return null;
        }

        IAsyncDisposable? held = wait ? await locks.TakeAsync(LockName, ct) : await locks.TryTakeAsync(LockName, ct);
        if (held is null)
        {
            return null;
        }

        await using (held)
        {
            Dictionary<string, int> counts = [];
            Dictionary<string, RetentionPeriod> periods = await guardDb.RunAsync(db => db.RetentionPeriods.AsNoTracking().ToDictionaryAsync(p => p.RuleKey, ct),
                cancellationToken: ct);
            foreach (IPersonalDataSweeper sweeper in services.GetServices<IPersonalDataSweeper>())
            {
                foreach (RetentionRule rule in sweeper.Rules)
                {
                    counts[rule.Key] = await SweepRuleAsync(sweeper, rule, rule.Key, periods.GetValueOrDefault(rule.Key), ct);
                }
            }

            List<string> plugins;
            await using (IGuardLease<IPersonalDataSweeper> lease = extensions.Lease<IPersonalDataSweeper>(services))
            {
                plugins = [.. lease.Items.Where(i => i.PluginKey is not null).Select(i => i.PluginKey!).Distinct(StringComparer.Ordinal)];
            }

            foreach (string plugin in plugins)
            {
                await using IGuardLease<IPersonalDataSweeper> lease = extensions.Lease<IPersonalDataSweeper>(services);
                foreach (IPersonalDataSweeper sweeper in lease.Items.Where(i => i.PluginKey == plugin).Select(i => i.Instance))
                {
                    foreach (RetentionRule rule in PluginRules(plugin, sweeper))
                    {
                        string key = $"{plugin}.{rule.Key}";
                        counts[key] = await SweepRuleAsync(sweeper, rule, key, periods.GetValueOrDefault(key), ct);
                    }
                }
            }

            await guardDb.RunAsync(async db =>
            {
                DateTime now = DateTime.UtcNow;
                foreach ((string key, int count) in counts.Where(c => c.Value >= 0))
                {
                    RetentionPeriod period = await db.RetentionPeriods.FirstOrDefaultAsync(p => p.RuleKey == key, ct)
                        ?? db.RetentionPeriods.Add(new RetentionPeriod { RuleKey = key }).Entity;
                    (period.LastSweptAt, period.LastCount) = (now, count);
                }

                await db.SaveChangesAsync(ct);
            }, requiresNew: true, ct);
            await audit.WriteAsync(SecurityAuditTypes.RetentionSwept, null, new { removed = counts.Where(c => c.Value != 0).ToDictionary() }, CancellationToken.None);
            return counts;
        }
    }

    /// <summary>One rule, batch after batch; -1 when it failed (the log says why, and the next sweep tries again).</summary>
    private async Task<int> SweepRuleAsync(IPersonalDataSweeper sweeper, RetentionRule rule, string key, RetentionPeriod? period, CancellationToken ct)
    {
        DateTime before = DateTime.UtcNow.AddDays(-DaysOf(rule, period));
        int total = 0;
        try
        {
            int removed;
            do
            {
                removed = await sweeper.SweepAsync(rule.Key, before, Batch, ct);
                total += removed;
            }
            while (removed >= Batch);
            return total;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Sweeping {Rule} failed after {Count} rows; the next sweep tries again.", key, total);
            return -1;
        }
    }
}

/// <summary>Sweeps once a day, the first time ten minutes after the server starts.</summary>
public sealed class PersonalDataRetentionWorker(IServiceScopeFactory scopes, ILogger<PersonalDataRetentionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMinutes(10), stoppingToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        using PeriodicTimer timer = new(TimeSpan.FromDays(1));
        do
        {
            try
            {
                await using AsyncServiceScope scope = scopes.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<PersonalDataRetention>().SweepAsync(wait: false, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "The retention sweep failed; it runs again tomorrow.");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
