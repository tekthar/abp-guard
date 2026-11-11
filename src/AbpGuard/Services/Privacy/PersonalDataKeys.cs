using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AbpGuard.Domain;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services.Privacy;

/// <summary>How many of Guard's rows a plugin rename moved to the plugins' new keys.</summary>
public sealed record PluginRenameCounts(int Stores, int Withdrawals, int RetentionPeriods, int SecondFactorMethods, int Erasures)
{
    public int Total => Stores + Withdrawals + RetentionPeriods + SecondFactorMethods + Erasures;
}

/// <summary>
/// What Guard keeps by a plugin's key, moved when the host renames its plugins (to app IDs, say): the records of
/// processing and consent withdrawals of a plugin's stores ("{plugin}.{store}"), its retention periods
/// ("{plugin}.{rule}"), the sent codes a second step may use ("{plugin}:{channel}"), and the stores of erasures not yet
/// finished. The host calls it at start, after Guard's migration, with each former key and its new one; it runs in one
/// transaction under the cluster's lock, and a second run moves nothing. Where a row already exists under the new key,
/// it wins and the former row stays. Finished erasures keep the keys they were done under.
/// </summary>
public sealed class PersonalDataKeys(GuardDb guardDb, IGuardLocks locks, ILogger<PersonalDataKeys> logger) : ITransientDependency
{
    public const string LockName = "plugin-keys";

    public async Task<PluginRenameCounts> RenamePluginsAsync(IReadOnlyDictionary<string, string> formerToAppId, CancellationToken cancellationToken = default)
    {
        List<(string Former, string Current)> renames = [.. formerToAppId
            .Where(p => p.Key.Length > 0 && p.Value.Length > 0 && p.Key != p.Value)
            .Select(p => (p.Key, p.Value))];
        if (renames.Count == 0)
        {
            return new(0, 0, 0, 0, 0);
        }

        await using IAsyncDisposable held = await locks.TakeAsync(LockName, cancellationToken);
        PluginRenameCounts counts = await guardDb.RunAsync(async db =>
        {
            int stores = 0, withdrawals = 0, periods = 0, methods = 0, erasures = 0;
            foreach ((string former, string current) in renames)
            {
                string prefix = former + ".";
                foreach (PrivacyStoreRecord record in await db.PrivacyStores.Where(s => s.StoreKey.StartsWith(prefix)).ToListAsync(cancellationToken))
                {
                    if (Renamed(record.StoreKey, former, current, '.') is { } key && !await db.PrivacyStores.AnyAsync(s => s.StoreKey == key, cancellationToken))
                    {
                        db.PrivacyStores.Remove(record);
                        db.PrivacyStores.Add(new PrivacyStoreRecord(key)
                        {
                            LegalBasis = record.LegalBasis, Sensitive = record.Sensitive, Notes = record.Notes, UpdatedAt = record.UpdatedAt, UpdatedBy = record.UpdatedBy,
                        });
                        stores++;
                    }
                }

                foreach (ConsentWithdrawal withdrawal in await db.ConsentWithdrawals.Where(w => w.StoreKey.StartsWith(prefix)).ToListAsync(cancellationToken))
                {
                    if (Renamed(withdrawal.StoreKey, former, current, '.') is { } key)
                    {
                        db.Entry(withdrawal).Property(w => w.StoreKey).CurrentValue = key;
                        withdrawals++;
                    }
                }

                foreach (RetentionPeriod period in await db.RetentionPeriods.Where(p => p.RuleKey.StartsWith(prefix)).ToListAsync(cancellationToken))
                {
                    if (Renamed(period.RuleKey, former, current, '.') is { } key && !await db.RetentionPeriods.AnyAsync(p => p.RuleKey == key, cancellationToken))
                    {
                        db.RetentionPeriods.Remove(period);
                        db.RetentionPeriods.Add(new RetentionPeriod
                        {
                            RuleKey = key, Days = period.Days, UpdatedAt = period.UpdatedAt, UpdatedBy = period.UpdatedBy, LastSweptAt = period.LastSweptAt,
                            LastCount = period.LastCount,
                        });
                        periods++;
                    }
                }

                // Deletes and inserts of the same table go before the next plugin's lookups see them.
                await db.SaveChangesAsync(cancellationToken);
            }

            if (await db.SecuritySettings.FirstOrDefaultAsync(cancellationToken) is { } settings)
            {
                List<string> renamed = Moved(settings.SecondFactorMethods, renames, ':', out int moved);
                if (moved > 0)
                {
                    settings.SecondFactorMethods = renamed;
                    methods = moved;
                }
            }

            foreach (PersonalDataErasureRecord erasure in await db.Erasures
                .Where(e => e.State == ErasureStates.Requested || e.State == ErasureStates.Running).ToListAsync(cancellationToken))
            {
                Dictionary<string, string> outcome = JsonSerializer.Deserialize<Dictionary<string, string>>(erasure.Stores) ?? [];
                List<string> keys = Moved([.. outcome.Keys], renames, '.', out int moved);
                if (moved > 0)
                {
                    erasure.Stores = JsonSerializer.Serialize(outcome.Keys.Zip(keys).ToDictionary(k => k.Second, k => outcome[k.First]));
                    erasures++;
                }
            }

            await db.SaveChangesAsync(cancellationToken);
            return new PluginRenameCounts(stores, withdrawals, periods, methods, erasures);
        }, requiresNew: true, cancellationToken, isTransactional: true);

        if (counts.Total > 0)
        {
            logger.LogInformation(
                "Moved Guard's rows to the plugins' new keys: {Stores} store records, {Withdrawals} consent withdrawals, {Periods} retention periods, " +
                "{Methods} second-step methods, {Erasures} unfinished erasures.",
                counts.Stores, counts.Withdrawals, counts.RetentionPeriods, counts.SecondFactorMethods, counts.Erasures);
        }

        return counts;
    }

    /// <summary>
    /// The key under the plugin's new key, or null when it isn't the former plugin's: "{former}{separator}{name}", the name
    /// one word with no dot (so another plugin's "{former}.{app}.{name}" is never taken for it).
    /// </summary>
    public static string? Renamed(string key, string former, string current, char separator) =>
        key.Length > former.Length + 1 && key.StartsWith(former, StringComparison.Ordinal) && key[former.Length] == separator
            && key.IndexOf('.', former.Length + 1) < 0
            ? current + key[former.Length..]
            : null;

    /// <summary>The keys renamed in place, a key whose new one is already there kept as it is; how many moved.</summary>
    private static List<string> Moved(List<string> keys, List<(string Former, string Current)> renames, char separator, out int moved)
    {
        List<string> result = [.. keys];
        HashSet<string> present = new(keys, StringComparer.Ordinal);
        moved = 0;
        for (int i = 0; i < result.Count; i++)
        {
            foreach ((string former, string current) in renames)
            {
                if (Renamed(result[i], former, current, separator) is { } key && present.Add(key))
                {
                    present.Remove(result[i]);
                    result[i] = key;
                    moved++;
                    break;
                }
            }
        }

        return result;
    }
}
