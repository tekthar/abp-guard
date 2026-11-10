using Microsoft.Extensions.Caching.Memory;

namespace AbpGuard.Services;

/// <summary>
/// A web session ended or stepped up on another server (docs/ha.md step 2): this server forgets its remembered check of
/// it, so the next request reads the session as it is now. After missed notices there's nothing to name; the checks
/// this server remembers end within seconds anyway.
/// </summary>
public sealed class WebSessionChanged(IMemoryCache cache) : IGuardBroadcastHandler
{
    public string Topic => WebSessions.Topic;

    public Task HandleAsync(string? detail, CancellationToken cancellationToken)
    {
        if (detail is not null)
        {
            cache.Remove(WebSessions.Key(detail));
        }

        return Task.CompletedTask;
    }
}
