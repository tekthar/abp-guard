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
