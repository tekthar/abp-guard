using Microsoft.Extensions.DependencyInjection;

namespace AbpGuard;

/// <summary>
/// Where Guard finds the extensions others give it: directory connectors (<see cref="Directories.IDirectoryConnector"/>)
/// and account-merge participants (<see cref="IAccountMergeParticipant"/>). The default has the host's own, from DI; a host
/// with plugins adds theirs.
/// </summary>
public interface IGuardExtensions
{
    /// <summary>
    /// The extensions of a kind, for one use: dispose the lease right after (<c>await using</c>), and never keep an item
    /// past it. A plugin's types must not outlive the call, or the plugin can't unload when it's disabled or upgraded.
    /// </summary>
    IGuardLease<T> Lease<T>(IServiceProvider services) where T : class;

    /// <summary>
    /// Whether an enabled plugin is running now: a host may hold one back (a safe mode, a plugin that failed to load), so
    /// it's enabled but leases nothing. An erasure waits for it rather than finish without its stores.
    /// </summary>
    bool IsRunning(string pluginKey) => true;

    /// <summary>Why the host holds every plugin back now (a safe mode), or null: an erasure doesn't start or resume meanwhile.</summary>
    string? PluginsHeldBecause => null;
}

/// <summary>The extensions leased: the host's own with no plugin key, then each plugin's with its key.</summary>
public interface IGuardLease<T> : IAsyncDisposable where T : class
{
    IEnumerable<(string? PluginKey, T Instance)> Items { get; }
}

/// <summary>The default: the host's own extensions from DI, nothing to release.</summary>
public sealed class ServiceGuardExtensions : IGuardExtensions
{
    public IGuardLease<T> Lease<T>(IServiceProvider services) where T : class => new ServiceLease<T>([.. services.GetServices<T>()]);

    private sealed class ServiceLease<T>(List<T> items) : IGuardLease<T> where T : class
    {
        public IEnumerable<(string? PluginKey, T Instance)> Items => items.Select(i => ((string?)null, i));

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
