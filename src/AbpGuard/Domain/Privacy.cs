using Volo.Abp.Domain.Entities;

namespace AbpGuard.Domain;

/// <summary>
/// What the controller may rest a store's processing on (PDPL): the person's consent, an agreement with
/// them, a legal obligation, a public task, a vital interest, or a legitimate interest. The controller decides.
/// </summary>
public static class LegalBases
{
    public const string Consent = "consent";
    public const string Agreement = "agreement";
    public const string LegalObligation = "legal-obligation";
    public const string PublicTask = "public-task";
    public const string VitalInterest = "vital-interest";
    public const string LegitimateInterest = "legitimate-interest";

    public static readonly IReadOnlyList<string> All = [Consent, Agreement, LegalObligation, PublicTask, VitalInterest, LegitimateInterest];
}

/// <summary>
/// What an admin recorded for a store of personal data: its legal basis, whether it may hold sensitive
/// data (health, genetic, credit, beliefs; null until someone decides), and notes. Kept by the store's key, so a store no
/// longer declared keeps its record, shown apart.
/// </summary>
public class PrivacyStoreRecord
{
    protected PrivacyStoreRecord()
    {
    }

    public PrivacyStoreRecord(string storeKey) => StoreKey = storeKey;

    public string StoreKey { get; private set; } = null!;
    public string? LegalBasis { get; set; }
    public bool? Sensitive { get; set; }
    public string? Notes { get; set; }
    public DateTime UpdatedAt { get; set; }
    public Guid? UpdatedBy { get; set; }
}

/// <summary>Who receives a destination's data, in which country, and whether that's outside the site's country.</summary>
public sealed record PrivacyDestination(string? Recipient, string? Country, bool OutsideCountry);

/// <summary>
/// The site's part of its record of processing (one row): the controller and the data protection officer, each a name and
/// a contact, the site's country, and who receives each destination's data; a privacy notice uses them
/// too). Guard is for sites anywhere: "outside" is outside the country set here.
/// </summary>
public class PrivacySettings
{
    public const int RowId = 1;

    public int Id { get; set; } = RowId;
    public string? ControllerName { get; set; }
    public string? ControllerContact { get; set; }
    public string? OfficerName { get; set; }
    public string? OfficerContact { get; set; }

    /// <summary>The country the site's data is to stay in, as the law it's under sees it; data going elsewhere leaves it.</summary>
    public string? Country { get; set; }

    /// <summary>By destination (<see cref="PersonalDataDestinations"/>): <c>mail</c>, <c>ai</c>, …, or a plugin's <c>service:{name}</c>.</summary>
    public Dictionary<string, PrivacyDestination> Destinations { get; set; } = [];

    public DateTime UpdatedAt { get; set; }
    public Guid? UpdatedBy { get; set; }
}

/// <summary>
/// A legal hold: while a law requires keeping a person's data, no erasure of them runs. On an
/// account, or on someone outside by an address; until a date, or until an admin releases it.
/// </summary>
public class LegalHold : Entity<Guid>
{
    protected LegalHold()
    {
    }

    public LegalHold(Guid id, Guid? accountId, string? address, string reason, DateTime? until, Guid createdBy) : base(id)
    {
        AccountId = accountId;
        Address = address;
        Reason = reason;
        Until = until;
        CreatedBy = createdBy;
        CreatedAt = DateTime.UtcNow;
    }

    public Guid? AccountId { get; private set; }

    /// <summary>A hold on someone outside the site: their email (lower case) or phone.</summary>
    public string? Address { get; private set; }

    public string Reason { get; private set; } = null!;
    public DateTime? Until { get; private set; }
    public Guid CreatedBy { get; private set; }
    public DateTime CreatedAt { get; private set; }
    public DateTime? ReleasedAt { get; set; }
    public Guid? ReleasedBy { get; set; }

    public bool ActiveAt(DateTime now) => ReleasedAt is null && (Until is null || Until > now);
}

/// <summary>
/// A version of the site's privacy notice: its text in each language (Markdown, a link, or both, as
/// JSON) as an admin published it. Never changed: a new text is a new version.
/// </summary>
public class PrivacyNoticeVersion
{
    public int Number { get; private set; }
    public string Texts { get; set; } = "{}";
    public DateTime PublishedAt { get; private set; } = DateTime.UtcNow;
    public Guid? PublishedBy { get; set; }
}

/// <summary>That someone accepted a version: an account, or an address (a portal's request, a sign-up), where, when, from where.</summary>
public class PrivacyAcceptance : Entity<Guid>
{
    protected PrivacyAcceptance()
    {
    }

    public PrivacyAcceptance(Guid id, Guid? accountId, string? address, int version, string where, string? ip) : base(id)
    {
        (AccountId, Address, Version, Where, Ip) = (accountId, address, version, where, ip);
        At = DateTime.UtcNow;
    }

    public Guid? AccountId { get; private set; }
    public string? Address { get; set; }
    public int Version { get; private set; }
    public string Where { get; private set; } = null!;
    public DateTime At { get; private set; }
    public string? Ip { get; set; }
}

/// <summary>A person withdrew their consent for a store whose legal basis is consent; an admin acts on it and marks it handled.</summary>
public class ConsentWithdrawal : Entity<Guid>
{
    protected ConsentWithdrawal()
    {
    }

    public ConsentWithdrawal(Guid id, Guid accountId, string storeKey) : base(id)
    {
        (AccountId, StoreKey) = (accountId, storeKey);
        At = DateTime.UtcNow;
    }

    public Guid AccountId { get; private set; }
    public string StoreKey { get; private set; } = null!;
    public DateTime At { get; private set; }
    public DateTime? HandledAt { get; set; }
    public Guid? HandledBy { get; set; }
    public string? Note { get; set; }
}

/// <summary>The security log's feed: where it goes, its secret (protected), and how far it got.</summary>
public class SecurityFeedSettings
{
    public int Id { get; set; } = 1;
    public string? Url { get; set; }
    public bool Enabled { get; set; }
    public string? ProtectedSecret { get; set; }
    public DateTime? CursorTime { get; set; }
    public Guid? CursorId { get; set; }
    public DateTime? LastSentAt { get; set; }
    public string? LastError { get; set; }
    public DateTime? FailingSince { get; set; }
}

/// <summary>Security alerts: how far the log was checked, and when each kind was last told (JSON).</summary>
public class SecurityAlertState
{
    public int Id { get; set; } = 1;
    public DateTime CheckedUpTo { get; set; }
    public string Sent { get; set; } = "{}";
}

/// <summary>
/// The site's retention: whether an admin confirmed the periods (an upgraded site sweeps nothing until
/// one does; a new site starts confirmed, with the defaults), one row.
/// </summary>
public class RetentionSettings
{
    public const int RowId = 1;

    public int Id { get; set; } = RowId;
    public DateTime? ConfirmedAt { get; set; }

    /// <summary>Who confirmed; null when the site started with the defaults.</summary>
    public Guid? ConfirmedBy { get; set; }
}

/// <summary>A retention rule's period as the site set it, and its last sweep.</summary>
public class RetentionPeriod
{
    /// <summary>The rule's key: a module's own, or a plugin's as "{plugin}.{rule}".</summary>
    public string RuleKey { get; set; } = null!;

    /// <summary>Null keeps the rule's default.</summary>
    public int? Days { get; set; }

    public DateTime? UpdatedAt { get; set; }
    public Guid? UpdatedBy { get; set; }
    public DateTime? LastSweptAt { get; set; }
    public int LastCount { get; set; }
}

public static class ErasureStates
{
    /// <summary>The person asked; an admin erases or declines.</summary>
    public const string Requested = "requested";

    public const string Declined = "declined";

    /// <summary>Running, or stopped by a store that failed: resumed store by store.</summary>
    public const string Running = "running";

    public const string Done = "done";
}

/// <summary>
/// An erasure: asked for by the person or started by an admin, run store by store, and resumable when
/// a store fails. It keeps the subject (the account and its addresses) only until every store is done; then only its
/// pseudonym, its counts and who did it remain.
/// </summary>
public class PersonalDataErasureRecord : Entity<Guid>
{
    protected PersonalDataErasureRecord()
    {
    }

    public PersonalDataErasureRecord(Guid id, Guid? accountId, string? subject, string state) : base(id)
    {
        AccountId = accountId;
        Subject = subject;
        State = state;
        CreatedAt = DateTime.UtcNow;
    }

    /// <summary>Numbers the pseudonym: "Former person {Number}".</summary>
    public int Number { get; private set; }

    public Guid? AccountId { get; private set; }

    /// <summary>The subject as JSON (account, addresses, names) while the erasure isn't done; null after.</summary>
    public string? Subject { get; set; }

    public string State { get; set; } = null!;

    /// <summary>Each store's outcome as JSON: "done", or why it failed or has no eraser.</summary>
    public string Stores { get; set; } = "{}";

    /// <summary>The person's words when they asked, or an admin's reason for declining.</summary>
    public string? Reason { get; set; }

    public string? DeclinedReason { get; set; }
    public Guid? RequestedBy { get; set; }
    public DateTime CreatedAt { get; private set; }
    public Guid? DecidedBy { get; set; }
    public DateTime? StartedAt { get; set; }
    public DateTime? FinishedAt { get; set; }
}
