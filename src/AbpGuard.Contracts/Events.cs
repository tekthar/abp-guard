namespace AbpGuard;

// Events in the event catalog published by guard. Plugins hear them distributed, from Guard's outbox
// (AddEventHandler<TEvent, THandler>()), or local, in the request (AddLocalEventHandler<TEvent, THandler>()).

/// <summary>
/// An event Guard publishes: its id is the same wherever and however often it's delivered, so a handler can
/// tell one it has seen. The host's event catalog finds Guard's events by their "Eto" suffix.
/// </summary>
public abstract record GuardEvent
{
    public Guid EventId { get; init; } = Guid.NewGuid();

    /// <summary>When it happened (UTC).</summary>
    public DateTime OccurredAt { get; init; } = DateTime.UtcNow;
}

public sealed record AccountCreatedEto(Guid AccountId, string Username, Guid DirectoryId) : GuardEvent;

public sealed record AccountUpdatedEto(Guid AccountId, string Username, Guid DirectoryId) : GuardEvent;

public sealed record AccountDeactivatedEto(Guid AccountId, string Username, string Reason) : GuardEvent;

public sealed record AccountReactivatedEto(Guid AccountId, string Username) : GuardEvent;

/// <summary>An account was folded into another: its references now name the survivor; Automatic when Guard did it.</summary>
public sealed record AccountMergedEto(Guid MergeId, Guid SourceId, string SourceUsername, Guid SurvivorId, string SurvivorUsername, bool Automatic) : GuardEvent;

public sealed record GroupCreatedEto(Guid GroupId, string Name) : GuardEvent;

public sealed record MembershipChangedEto(Guid GroupId, string GroupName) : GuardEvent;

public sealed record DirectorySyncCompletedEto(
    Guid DirectoryId,
    string DirectoryName,
    bool Succeeded,
    int UsersAdded,
    int UsersUpdated,
    int UsersDeactivated,
    int GroupsSynced,
    TimeSpan Duration,
    string? Error) : GuardEvent;
