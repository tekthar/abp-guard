namespace AbpGuard;

/// <summary>
/// Telling the site's other servers that something Guard keeps changed, so each forgets what it remembered of
/// it at once: a web session ended or stepped up ("web-session", with the session's hash). A shortcut, never the truth:
/// what's remembered expires on its own. The default has one server and tells no one; a host with several gives its own
///, and calls Guard's <see cref="IGuardBroadcastHandler"/>s when another server says so.
/// </summary>
public interface IGuardBroadcast
{
    void Notify(string topic, string? detail);
}

/// <summary>Acts on another server's notice of a topic. The detail is the notice's, or null when this server may have missed some.</summary>
public interface IGuardBroadcastHandler
{
    string Topic { get; }

    Task HandleAsync(string? detail, CancellationToken cancellationToken);
}

/// <summary>The default: a site of one server, so no one else to tell.</summary>
public sealed class SingleServerGuardBroadcast : IGuardBroadcast
{
    public void Notify(string topic, string? detail)
    {
    }
}
