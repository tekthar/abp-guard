using Casl;
using AbpGuard.Services;
using Xunit;

namespace AbpGuard.Tests;

/// <summary>Abilities kept between requests: only under the stamp they were built under, and only until a grant runs out.</summary>
public class AbilityCacheTests
{
    private static readonly Guid Person = Guid.NewGuid();
    private static Ability Built() => new AbilityBuilder(GuardSubjects.Registry, GuardSubjects.Options).Build();

    [Fact]
    public void A_kept_ability_is_used_under_the_same_stamp()
    {
        AbilityCache cache = new();
        Ability ability = Built();
        Assert.False(cache.TryGet(Person, 7, out _));
        cache.Set(Person, 7, ability, until: null);
        Assert.True(cache.TryGet(Person, 7, out Ability kept));
        Assert.Same(ability, kept);
    }

    [Fact]
    public void A_new_stamp_drops_what_was_kept()
    {
        AbilityCache cache = new();
        cache.TryGet(Person, 7, out _);
        cache.Set(Person, 7, Built(), until: null);
        Assert.False(cache.TryGet(Person, 8, out _));
        Assert.False(cache.TryGet(Person, 7, out _)); // gone, not just hidden: a stamp seen again starts empty
    }

    [Fact]
    public void An_ability_built_under_an_old_stamp_is_not_kept()
    {
        AbilityCache cache = new();
        cache.TryGet(Person, 7, out _);
        cache.TryGet(Guid.NewGuid(), 8, out _); // another request read the newer stamp meanwhile
        cache.Set(Person, 7, Built(), until: null);
        Assert.False(cache.TryGet(Person, 8, out _));
    }

    [Fact]
    public void A_request_with_an_old_stamp_never_gets_one_built_under_a_newer_one()
    {
        AbilityCache cache = new();
        cache.TryGet(Person, 8, out _);
        cache.Set(Person, 8, Built(), until: null);
        Assert.False(cache.TryGet(Person, 7, out _));
    }

    [Fact]
    public void A_grant_that_runs_out_ends_the_kept_ability()
    {
        AbilityCache cache = new();
        cache.TryGet(Person, 7, out _);
        cache.Set(Person, 7, Built(), until: DateTime.UtcNow.AddMilliseconds(-1));
        Assert.False(cache.TryGet(Person, 7, out _));
        cache.Set(Person, 7, Built(), until: DateTime.UtcNow.AddHours(1));
        Assert.True(cache.TryGet(Person, 7, out _));
    }
}
