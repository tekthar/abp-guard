using Volo.Abp.Domain.Entities;

namespace AbpGuard.Domain;

/// <summary>How an address came to an account.</summary>
public static class AccountEmailSources
{
    /// <summary>The person added it, and confirmed it from a link mailed to it.</summary>
    public const string Person = "person";

    /// <summary>An admin added it: verified at once.</summary>
    public const string Admin = "admin";

    /// <summary>It came with an account merged into this one.</summary>
    public const string Merge = "merge";
}

/// <summary>
/// An address an account has besides its directory's. Only verified ones count: for matching, for where mail
/// goes, and for organizations by domain. A verified address belongs to one account.
/// </summary>
public class AccountEmail : Entity<Guid>
{
    protected AccountEmail()
    {
    }

    public AccountEmail(Guid id, Guid accountId, string email, string source, Guid? addedBy) : base(id)
    {
        AccountId = accountId;
        Email = email.Trim();
        NormalizedEmail = GuardConstants.Normalize(email);
        Source = source;
        AddedBy = addedBy;
        AddedAt = DateTime.UtcNow;
    }

    public Guid AccountId { get; set; }
    public string Email { get; private set; } = null!;
    public string NormalizedEmail { get; private set; } = null!;

    /// <summary>One of <see cref="AccountEmailSources"/>.</summary>
    public string Source { get; private set; } = null!;

    /// <summary>When it was confirmed; null while a link waits to be followed.</summary>
    public DateTime? VerifiedAt { get; set; }

    public DateTime AddedAt { get; private set; }
    public Guid? AddedBy { get; private set; }
}

/// <summary>Where a merge has got to: the host's own modules move in one transaction, plugins after it.</summary>
public static class MergeStates
{
    public const string Done = "done";

    /// <summary>A plugin failed or was off: resuming the merge asks the plugins that haven't finished.</summary>
    public const string Incomplete = "incomplete";
}

/// <summary>A part of a merge: what a participant moved, or why it hasn't yet.</summary>
public sealed class MergeStep
{
    /// <summary>"guard", "platform" or "projects" for the host's own modules; a plugin's key for a plugin.</summary>
    public string Key { get; set; } = "";

    public bool Plugin { get; set; }

    /// <summary>done, failed, or off (the plugin wasn't enabled when it was asked).</summary>
    public string State { get; set; } = "";

    public string? Error { get; set; }
    public DateTime At { get; set; }
    public List<MergeStepCount> Counts { get; set; } = [];
}

public sealed class MergeStepCount
{
    public string Key { get; set; } = "";
    public int Count { get; set; }
    public string? Label { get; set; }
}

/// <summary>
/// One account folded into another, as it happened: who the source was, who merged it (or why it was
/// automatic), and what each module and plugin moved. There's no undo; this is the record.
/// </summary>
public class AccountMergeRecord : Entity<Guid>
{
    protected AccountMergeRecord()
    {
    }

    public AccountMergeRecord(Guid id, Account source, Account survivor, Guid? actorId, string reason) : base(id)
    {
        SourceId = source.Id;
        SurvivorId = survivor.Id;
        SourceUsername = source.Username;
        SourceDisplayName = source.DisplayName.Length > 256 ? source.DisplayName[..256] : source.DisplayName;
        SourceEmail = source.Email;
        SourceDirectoryId = source.DirectoryId;
        SurvivorUsername = survivor.Username;
        ActorId = actorId;
        Reason = reason;
        StartedAt = DateTime.UtcNow;
        State = MergeStates.Incomplete;
    }

    public Guid SourceId { get; private set; }
    public Guid SurvivorId { get; private set; }
    public string SourceUsername { get; private set; } = null!;
    public string SourceDisplayName { get; private set; } = null!;
    public string? SourceEmail { get; private set; }
    public Guid SourceDirectoryId { get; private set; }
    public string SurvivorUsername { get; private set; } = null!;

    /// <summary>The admin who merged; null when Guard merged a placeholder by itself.</summary>
    public Guid? ActorId { get; private set; }

    /// <summary>"admin", or for an automatic merge what found the match: sign-up, directory sync, account created, address added.</summary>
    public string Reason { get; private set; } = null!;

    public DateTime StartedAt { get; private set; }
    public DateTime? FinishedAt { get; set; }

    /// <summary>One of <see cref="MergeStates"/>.</summary>
    public string State { get; set; } = null!;

    public List<MergeStep> Steps { get; set; } = [];
}
