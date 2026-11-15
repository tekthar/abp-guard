using AbpGuard.Acting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Volo.Abp.DistributedLocking;
using Volo.Abp.EntityFrameworkCore;
using Volo.Abp.Modularity;

namespace AbpConnections;

/// <summary>
/// Connections to outside systems. The application lists this module in its DependsOn, maps the tables in its own context
/// (<see cref="ConnectionsModel.ConfigureConnections"/>, the context implementing <see cref="IConnectionsDbContext"/> and
/// standing in for it), registers its connection kinds (<see cref="IConnectionKind"/> as services, or an
/// <see cref="IConnectionKinds"/> of its own), and uses <see cref="ConnectionManager"/> with its own checks of who may.
/// The outbound guard's settings are read from <c>Network</c> (<see cref="OutboundOptions"/>); the client that tests and
/// signs in is <see cref="ConnectionsOptions.HttpClientName"/>, guarded, with a 30-second timeout.
/// </summary>
[DependsOn(typeof(AbpEntityFrameworkCoreModule), typeof(AbpDistributedLockingAbstractionsModule))]
public class AbpConnectionsModule : AbpModule
{
    public override void ConfigureServices(ServiceConfigurationContext context)
    {
        // Defaults a host replaces by registering its own.
        context.Services.TryAddTransient<IConnectionKinds, ServiceConnectionKinds>();
        context.Services.TryAddTransient<IConnectionLocks, DistributedConnectionLocks>();
        // The security audit is AbpGuard's where the application has it; without, nothing is recorded.
        context.Services.TryAddTransient<ISecurityAudit, NoSecurityAudit>();
        context.Services.AddOptions<ConnectionsOptions>();
        context.Services.Configure<OutboundOptions>(context.Services.GetConfiguration().GetSection("Network"));
        context.Services.AddHttpClient(new ConnectionsOptions().HttpClientName, client => client.Timeout = TimeSpan.FromSeconds(30)).RefusePrivateAddresses();
    }
}

/// <summary>No security audit: an application without AbpGuard's (or one of its own).</summary>
public sealed class NoSecurityAudit : ISecurityAudit
{
    public Task WriteAsync(string type, AuditTarget? target, object? detail, CancellationToken cancellationToken = default) => Task.CompletedTask;
}

/// <summary>The kinds registered as services (<see cref="IConnectionKind"/>), each keyed by its type.</summary>
public sealed class ServiceConnectionKinds(IEnumerable<IConnectionKind> registered) : IConnectionKinds
{
    public Task<IConnectionKindsLease> LeaseAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IConnectionKindsLease>(new Lease([.. registered.Select(k => new ConnectionKindEntry(k.Type, k, null))]));

    private sealed class Lease(IReadOnlyList<ConnectionKindEntry> items) : IConnectionKindsLease
    {
        public IReadOnlyList<ConnectionKindEntry> Items { get; } = items;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

/// <summary>The refresh lock on ABP's distributed lock: waits until it's free (or the call is cancelled).</summary>
public sealed class DistributedConnectionLocks(IAbpDistributedLock locks) : IConnectionLocks
{
    public async Task<IAsyncDisposable> TakeAsync(string name, CancellationToken cancellationToken)
    {
        while (true)
        {
            if (await locks.TryAcquireAsync(name, TimeSpan.FromSeconds(30), cancellationToken) is { } held)
            {
                return held;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }
}
