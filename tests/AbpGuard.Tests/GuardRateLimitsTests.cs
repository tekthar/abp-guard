using Microsoft.Extensions.Configuration;

namespace AbpGuard.Tests;

/// <summary>Guard's default limits, counted in memory on a host without a database.</summary>
public class GuardRateLimitsTests
{
    private static PostgresGuardRateLimits Limits() => new(new ConfigurationBuilder().Build());

    [Fact]
    public async Task A_key_takes_up_to_its_maximum_in_the_window()
    {
        PostgresGuardRateLimits limits = Limits();

        Assert.True(await limits.TryTakeAsync("sign-in|u:dana", 2, TimeSpan.FromMinutes(15)));
        Assert.True(await limits.TryTakeAsync("sign-in|u:dana", 2, TimeSpan.FromMinutes(15)));
        Assert.False(await limits.TryTakeAsync("sign-in|u:dana", 2, TimeSpan.FromMinutes(15)));
        Assert.True(await limits.TryTakeAsync("sign-in|u:sam", 2, TimeSpan.FromMinutes(15)));
    }

    [Fact]
    public async Task Added_hits_count_and_a_reset_forgets_them()
    {
        PostgresGuardRateLimits limits = Limits();
        await limits.AddAsync("second-factor-send|u:1");
        await limits.AddAsync("second-factor-send|u:1");

        Assert.Equal(2, await limits.CountAsync("second-factor-send|u:1", TimeSpan.FromMinutes(15)));
        // A shorter window asked first doesn't drop hits a longer one still counts.
        Assert.Equal(2, await limits.CountAsync("second-factor-send|u:1", TimeSpan.FromSeconds(30)));
        Assert.Equal(2, await limits.CountAsync("second-factor-send|u:1", TimeSpan.FromHours(1)));

        await limits.ResetAsync("second-factor-send|u:1");
        Assert.Equal(0, await limits.CountAsync("second-factor-send|u:1", TimeSpan.FromMinutes(15)));
    }

    [Fact]
    public async Task A_window_is_at_most_a_day()
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => Limits().CountAsync("k", TimeSpan.FromDays(2)));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => Limits().TryTakeAsync("k", 1, TimeSpan.Zero));
    }
}
