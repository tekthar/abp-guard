using Volo.Abp.Domain.Entities;

namespace AbpGuard.Domain;

/// <summary>
/// A group's second-factor mode: <c>off</c>; <c>optional</c>, offered at sign-in and never asked;
/// <c>required</c>; <c>strong</c>, required with a strong method (the authenticator app). A person follows the strictest
/// of every group they're in.
/// </summary>
public static class TwoFactorModes
{
    public const string Off = "off";
    public const string Optional = "optional";
    public const string Required = "required";
    public const string Strong = "strong";

    /// <summary>Every mode, in order from the least strict: a mode's place is its <see cref="Rank"/>.</summary>
    public static readonly IReadOnlyList<string> All = [Off, Optional, Required, Strong];

    public static int Rank(string? mode) => mode switch
    {
        Optional => 1,
        Required => 2,
        Strong => 3,
        _ => 0,
    };

    public static string Strictest(IEnumerable<string?> modes) => All[modes.Select(Rank).DefaultIfEmpty(0).Max()];

    public static bool Asks(string mode) => Rank(mode) >= Rank(Required);
}

/// <summary>
/// The kinds of second factor. A recovery code isn't a factor of its own: it stands in for one, once. Codes
/// sent by <c>email</c> or another channel (its key, <c>messaging:sms</c>) aren't set up: a site allows them, and anyone
/// it can reach that way may use them.
/// </summary>
public static class SecondFactorKinds
{
    public const string App = "app";
    public const string Recovery = "recovery";
    public const string Email = "email";

    /// <summary>The methods a strong mode accepts.</summary>
    public static bool IsStrong(string kind) => kind == App;

    /// <summary>A method whose code is sent: email, or a channel's key.</summary>
    public static bool IsSent(string? method) => method is { Length: > 0 } && method is not (App or Recovery);
}

/// <summary>
/// A code sent by email, SMS or WhatsApp for a second step: its SHA-256 only, for ten minutes, good once.
/// Sending a new one for the same method replaces it.
/// </summary>
public class SentCode : Entity<Guid>
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    protected SentCode()
    {
    }

    public SentCode(Guid id, Guid accountId, string method, string codeHash) : base(id)
    {
        AccountId = accountId;
        Method = method;
        CodeHash = codeHash;
        CreatedAt = DateTime.UtcNow;
        ExpiresAt = CreatedAt + Lifetime;
    }

    public Guid AccountId { get; private set; }

    /// <summary><c>email</c>, or the channel's key.</summary>
    public string Method { get; private set; } = null!;

    public string CodeHash { get; private set; } = null!;
    public DateTime CreatedAt { get; private set; }
    public DateTime ExpiresAt { get; private set; }
    public DateTime? UsedAt { get; set; }
}

/// <summary>
/// One of a person's second factors. The authenticator app's secret is kept encrypted with the site's key
/// ring; a factor isn't used until its first code was right (<see cref="ConfirmedAt"/>).
/// </summary>
public class SecondFactor : Entity<Guid>
{
    protected SecondFactor()
    {
    }

    public SecondFactor(Guid id, Guid accountId, string kind, string? protectedSecret) : base(id)
    {
        AccountId = accountId;
        Kind = kind;
        ProtectedSecret = protectedSecret;
        CreatedAt = DateTime.UtcNow;
    }

    public Guid AccountId { get; private set; }
    public string Kind { get; private set; } = null!;
    public string? ProtectedSecret { get; private set; }
    public DateTime CreatedAt { get; private set; }

    /// <summary>When its first code was right; until then it's being set up and isn't asked for.</summary>
    public DateTime? ConfirmedAt { get; set; }

    public DateTime? LastUsedAt { get; set; }

    /// <summary>The app's last time step used, so a code is good once.</summary>
    public long LastStep { get; set; }
}

/// <summary>A recovery code: its SHA-256 only, good once.</summary>
public class RecoveryCode : Entity<Guid>
{
    protected RecoveryCode()
    {
    }

    public RecoveryCode(Guid id, Guid accountId, string hash) : base(id)
    {
        AccountId = accountId;
        Hash = hash;
        CreatedAt = DateTime.UtcNow;
    }

    public Guid AccountId { get; private set; }
    public string Hash { get; private set; } = null!;
    public DateTime CreatedAt { get; private set; }
    public DateTime? UsedAt { get; set; }
}

/// <summary>
/// A password that was right, waiting for its second step: the ticket's SHA-256, for five minutes and five
/// tries, for the client that checked the password. Setting up a second factor with it proves the step too.
/// </summary>
public class SignInTicket : Entity<Guid>
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);
    public const int MaxAttempts = 5;

    protected SignInTicket()
    {
    }

    public SignInTicket(Guid id, Guid accountId, string ticketHash, string client, string? scopes, string? ip) : base(id)
    {
        AccountId = accountId;
        TicketHash = ticketHash;
        Client = client;
        Scopes = scopes;
        Ip = ip;
        CreatedAt = DateTime.UtcNow;
        ExpiresAt = CreatedAt + Lifetime;
    }

    public Guid AccountId { get; private set; }
    public string TicketHash { get; private set; } = null!;

    /// <summary><c>web</c> for the web's session, else the OAuth client that asked (<c>mobile</c>, <c>web</c>).</summary>
    public string Client { get; private set; } = null!;

    /// <summary>The scopes the password grant asked for, space-separated.</summary>
    public string? Scopes { get; private set; }

    public string? Ip { get; private set; }
    public DateTime CreatedAt { get; private set; }
    public DateTime ExpiresAt { get; private set; }
    public int Attempts { get; set; }

    /// <summary>When a second factor was set up with this ticket, which proves the step without another code.</summary>
    public DateTime? ProvedAt { get; set; }

    public bool Usable(DateTime now) => now < ExpiresAt && Attempts < MaxAttempts;
}
