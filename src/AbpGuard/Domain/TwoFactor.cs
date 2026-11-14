using Volo.Abp.Domain.Entities;

namespace AbpGuard.Domain;

/// <summary>
/// A group's second-factor mode: <c>off</c>; <c>optional</c>, offered at sign-in and never asked;
/// <c>required</c>; <c>strong</c>, required with a strong method (a passkey or the authenticator app). A person follows the
/// strictest of every group they're in.
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
/// it can reach that way may use them. A <c>passkey</c> (WebAuthn) and the authenticator <c>app</c> are the strong ones.
/// </summary>
public static class SecondFactorKinds
{
    public const string App = "app";
    public const string Passkey = "passkey";
    public const string Recovery = "recovery";
    public const string Email = "email";

    /// <summary>The methods a strong mode, and a strong step-up, accept: a passkey and the authenticator app.</summary>
    public static bool IsStrong(string? kind) => kind is App or Passkey;

    /// <summary>A method whose code is sent: email, or a channel's key.</summary>
    public static bool IsSent(string? method) => method is { Length: > 0 } && method is not (App or Passkey or Recovery);
}

/// <summary>
/// A person's passkey (a WebAuthn credential), registered discoverable and with user verification: its credential id
/// and public key (COSE), the signature count it last gave, its authenticator's AAGUID (which names the provider), the
/// transports it said, whether it may be and is synced (its backup flags), the name the person gave it, and when it was
/// made and last used. A passkey is personal data.
/// </summary>
public class Passkey : Entity<Guid>
{
    public const int NameLength = 100;

    protected Passkey()
    {
    }

    public Passkey(Guid id, Guid accountId, byte[] credentialId, byte[] publicKey, long signCount, Guid aaGuid, string? transports, bool backupEligible,
        bool backedUp, string name) : base(id)
    {
        AccountId = accountId;
        CredentialId = credentialId;
        PublicKey = publicKey;
        SignCount = signCount;
        AaGuid = aaGuid;
        Transports = transports;
        BackupEligible = backupEligible;
        BackedUp = backedUp;
        Name = name;
        CreatedAt = DateTime.UtcNow;
    }

    public Guid AccountId { get; private set; }

    /// <summary>The credential's id, as the device gave it.</summary>
    public byte[] CredentialId { get; private set; } = null!;

    /// <summary>The credential's public key, COSE-encoded.</summary>
    public byte[] PublicKey { get; private set; } = null!;

    /// <summary>The signature count the device last gave: a later one must be higher, unless the device keeps none (0).</summary>
    public long SignCount { get; set; }

    /// <summary>The authenticator's model (all zeros when it doesn't say).</summary>
    public Guid AaGuid { get; private set; }

    /// <summary>How the device said it's reached (internal, hybrid, usb…), comma-separated.</summary>
    public string? Transports { get; private set; }

    /// <summary>Whether the passkey may be synced to the person's other devices.</summary>
    public bool BackupEligible { get; private set; }

    /// <summary>Whether it is synced now, as the device last said.</summary>
    public bool BackedUp { get; set; }

    public string Name { get; set; } = null!;
    public DateTime CreatedAt { get; private set; }
    public DateTime? LastUsedAt { get; set; }
}

/// <summary>
/// A passkey ceremony's challenge, waiting for the device's answer: its SHA-256, the options sent (to check the answer
/// against), and what asked for it. Good once, for five minutes, for the session or the sign-in's ticket that asked
/// (<see cref="Binding"/>) and the purpose it was asked for.
/// </summary>
public class PasskeyChallenge : Entity<Guid>
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    protected PasskeyChallenge()
    {
    }

    public PasskeyChallenge(Guid id, Guid accountId, string challengeHash, string purpose, string binding, string options) : base(id)
    {
        AccountId = accountId;
        ChallengeHash = challengeHash;
        Purpose = purpose;
        Binding = binding;
        Options = options;
        CreatedAt = DateTime.UtcNow;
        ExpiresAt = CreatedAt + Lifetime;
    }

    public Guid AccountId { get; private set; }

    /// <summary>SHA-256 of the challenge's bytes, in hex.</summary>
    public string ChallengeHash { get; private set; } = null!;

    /// <summary><c>register</c>, <c>step-up</c>, <c>second-step</c> or <c>enrol</c>.</summary>
    public string Purpose { get; private set; } = null!;

    /// <summary>What asked: <c>s:</c> and a web session's id, <c>a:</c> and an app's sign-in, or <c>t:</c> and a ticket's hash.</summary>
    public string Binding { get; private set; } = null!;

    /// <summary>The options sent, as JSON: the answer is checked against them.</summary>
    public string Options { get; private set; } = null!;

    public DateTime CreatedAt { get; private set; }
    public DateTime ExpiresAt { get; private set; }
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
