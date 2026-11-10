using Microsoft.Extensions.DependencyInjection;

namespace AbpGuard.Tests;

/// <summary>Guard's default extensions: the host's own from DI, with no plugin key, and nothing to release.</summary>
public class GuardExtensionsTests
{
    [Fact]
    public async Task The_default_lease_has_the_hosts_own_extensions()
    {
        ServiceProvider services = new ServiceCollection()
            .AddSingleton<IAccountMergeParticipant, Participant>().AddSingleton<IAccountMergeParticipant, Participant>().BuildServiceProvider();

        await using IGuardLease<IAccountMergeParticipant> lease = new ServiceGuardExtensions().Lease<IAccountMergeParticipant>(services);

        Assert.Equal(2, lease.Items.Count());
        Assert.All(lease.Items, i => Assert.Null(i.PluginKey));
    }

    private sealed class Participant : IAccountMergeParticipant
    {
        public Task<IReadOnlyList<AccountMergeCount>> PreviewAsync(Guid sourceId, Guid survivorId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AccountMergeCount>>([]);

        public Task<IReadOnlyList<AccountMergeCount>> MergeAsync(AccountMerge merge, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AccountMergeCount>>([]);
    }
}
