using Microsoft.Extensions.Configuration;

namespace AbpGuard.Tests;

/// <summary>Guard's default locks: without a database (a test host) every lock is granted, one process being a cluster of one.</summary>
public class GuardLocksTests
{
    [Fact]
    public async Task Without_a_database_every_lock_is_granted()
    {
        PostgresGuardLocks locks = new(new ConfigurationBuilder().Build());

        await using IAsyncDisposable? tried = await locks.TryTakeAsync("directory-sync-schedule", CancellationToken.None);
        await using IAsyncDisposable taken = await locks.TakeAsync("directory-sync-schedule", CancellationToken.None);

        Assert.NotNull(tried);
        Assert.NotNull(taken);
    }
}
