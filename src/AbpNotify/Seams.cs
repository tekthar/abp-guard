using Volo.Abp.DependencyInjection;

namespace AbpNotify;

// What the notices need from the application that hosts them: how a message is rendered and sent (the messenger, in
// AbpNotify.Contracts), who people are, how a digest reads, whether a person can be reached on a channel, and how the
// other servers are woken. The application fills each; the notices' rules stay here.

/// <summary>The events people choose how to hear of, in the order they're shown; each module adds its own.</summary>
public sealed class NoticeEventOptions
{
    public List<string> Events { get; } = [];

    public void Add(IEnumerable<string> events) => Events.AddRange(events.Where(e => !Events.Contains(e)));
}

/// <summary>
/// The site's defaults for sending notices, from configuration until a site admin sets them: how long after a message
/// to wait and gather what follows into one, and how many a person gets an hour before the rest go to their digest.
/// </summary>
public sealed class NoticeOptions
{
    public int WindowSeconds { get; set; } = 120;
    public int MailsPerHour { get; set; } = 30;
}

/// <summary>The names the notices use for the application's mail channel and templates.</summary>
public sealed class NotifyOptions
{
    /// <summary>The channel a digest always goes by, and what's told now when a person's own channel can't take it.</summary>
    public string MailChannel { get; set; } = "email";

    /// <summary>The template for several notices in one message, or a digest.</summary>
    public string DigestTemplate { get; set; } = "notice.digest";

    /// <summary>Added to a template's key for its short form on a chat channel; a template without one goes by mail.</summary>
    public string ShortSuffix { get; set; } = ".message";

    /// <summary>The named HTTP client the chat and push channels call out with: give it the application's outbound guard.</summary>
    public string HttpClientName { get; set; } = "Notify";

    /// <summary>What the application is called where a channel says what it does ("this server" unless it names itself).</summary>
    public string ApplicationName { get; set; } = "this server";
}

/// <summary>The application's people.</summary>
public interface INotifyPeople
{
    Task<IReadOnlyList<NotifyPerson>> PeopleAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken);

    /// <summary>People's names as the inbox shows who acted; those it doesn't know are left out.</summary>
    Task<IReadOnlyDictionary<Guid, string>> NamesAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken);

    /// <summary>The site's time zone, for people who chose none.</summary>
    string SiteTimeZone { get; }
}

/// <summary>How the application's digest reads: the model its digest template is rendered with, for these notices.</summary>
public interface INoticeDigests
{
    IReadOnlyDictionary<string, object?> Model(IReadOnlyList<Notice> notices, bool digest);
}

/// <summary>Whether a person has a verified address on a channel that's set up, so what's told now may go there.</summary>
public interface INotifyReach
{
    Task<bool> ReachesAsync(Guid accountId, string channel, CancellationToken cancellationToken);
}

/// <summary>Wakes the notices' sender on the application's other servers.</summary>
public interface INoticeBroadcast
{
    void WakeOthers();
}

/// <summary>
/// Wakes the sender when there's something to look at: on this server, and through <see cref="INoticeBroadcast"/> on
/// the others. Without a broadcast nothing breaks: each sender looks every second anyway.
/// </summary>
public sealed class NoticeWakeup(IEnumerable<INoticeBroadcast> broadcasts) : ISingletonDependency
{
    private readonly SemaphoreSlim _wake = new(0, 1);

    /// <summary>Wakes the sender on every server.</summary>
    public void Signal()
    {
        WakeHere();
        foreach (INoticeBroadcast broadcast in broadcasts)
        {
            broadcast.WakeOthers();
        }
    }

    /// <summary>Wakes this server's sender only (another server had something to send).</summary>
    public void WakeHere()
    {
        try
        {
            _wake.Release();
        }
        catch (SemaphoreFullException)
        {
        }
    }

    /// <summary>Waits for a wake, or for <paramref name="most"/>.</summary>
    public Task<bool> WaitAsync(TimeSpan most, CancellationToken cancellationToken) => _wake.WaitAsync(most, cancellationToken);
}
