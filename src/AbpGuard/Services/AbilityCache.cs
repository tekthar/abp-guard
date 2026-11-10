using System.Collections.Concurrent;
using Casl;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>
/// Abilities kept between requests, per account and one for Anonymous visitors. An ability is used only by a
/// request that read the same permission stamp it was built under, and only until the first of its grants with a "valid
/// until" runs out. When requests start reading another stamp, the kept abilities are dropped. CASL .NET's abilities are
/// immutable, so concurrent requests share them, with the checks they've compiled.
/// </summary>
[ExposeServices(typeof(AbilityCache), typeof(IPermissionStamp))]
public sealed class AbilityCache : ISingletonDependency, IPermissionStamp
{
    /// <summary>How many abilities are kept at most; past that, all are dropped and built again as needed.</summary>
    public const int MaxEntries = 10_000;

    private sealed record Entry(long Stamp, Ability Ability, DateTime? Until);

    private readonly ConcurrentDictionary<Guid, Entry> _entries = new();
    private readonly Lock _gate = new();
    private long _stamp = long.MinValue;

    /// <summary>The stamp requests last read; what's kept elsewhere for building abilities (the project tree) is checked against it.</summary>
    public long Stamp => Interlocked.Read(ref _stamp);

    /// <summary>The ability kept for this principal under exactly this stamp, if there's one and its grants haven't run out.</summary>
    public bool TryGet(Guid principal, long stamp, out Ability ability)
    {
        Moved(stamp);
        if (_entries.TryGetValue(principal, out Entry? entry) && entry.Stamp == stamp && (entry.Until is null || entry.Until > DateTime.UtcNow))
        {
            ability = entry.Ability;
            return true;
        }

        ability = null!;
        return false;
    }

    /// <summary>Keeps an ability built under this stamp, if it's still the stamp requests read.</summary>
    public void Set(Guid principal, long stamp, Ability ability, DateTime? until)
    {
        lock (_gate)
        {
            if (_stamp != stamp)
            {
                return;
            }

            if (_entries.Count >= MaxEntries)
            {
                _entries.Clear();
            }

            _entries[principal] = new Entry(stamp, ability, until);
        }
    }

    /// <summary>A request read this stamp: when it isn't the one before, the kept abilities are dropped (none of them can match now).</summary>
    private void Moved(long stamp)
    {
        if (Interlocked.Read(ref _stamp) == stamp)
        {
            return;
        }

        lock (_gate)
        {
            if (_stamp != stamp)
            {
                _entries.Clear();
                Interlocked.Exchange(ref _stamp, stamp);
            }
        }
    }
}
