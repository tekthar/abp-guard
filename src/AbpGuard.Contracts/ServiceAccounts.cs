namespace AbpGuard;

/// <summary>
/// A service account to make: its username, and optionally its display name and whether an automated actor works
/// through it (an agent's account). Members are added by name, so hosts keep building it as fields are added.
/// </summary>
public sealed record ServiceAccountInput(string Username)
{
    public string? DisplayName { get; init; }

    /// <summary>An agent's account: a service account an automated actor works through, which holds no tokens.</summary>
    public bool Agent { get; init; }
}

/// <summary>
/// A token to make for a service account: its name, read or write ("read", "write"), how many days it lives (within
/// the site's longest), the resources it's limited to (the host's projects, say; none for all) and the tools (none for all).
/// </summary>
public sealed record ServiceAccountTokenInput(Guid AccountId, string Name, int Days)
{
    public string Access { get; init; } = "write";

    public IReadOnlyList<Guid>? ResourceIds { get; init; }

    public IReadOnlyList<string>? Tools { get; init; }
}

/// <summary>A service account's token as a list shows it: never its secret.</summary>
public sealed record ServiceAccountTokenInfo(
    Guid Id, Guid AccountId, string Name, string Prefix, string Access, DateTime ExpiresAt, DateTime CreatedAt, DateTime? LastUsedAt,
    DateTime? RevokedAt, bool Active, IReadOnlyList<Guid>? ResourceIds, IReadOnlyList<string>? Tools);

/// <summary>A token just made, with its secret: the only time the secret is given.</summary>
public sealed record NewServiceAccountToken(ServiceAccountTokenInfo Token, string Secret);

/// <summary>
/// Service accounts the host makes without going through HTTP. Each has no password and no address, so it can't sign in
/// and no reset or mail reaches it.
/// </summary>
public interface IServiceAccounts
{
    /// <summary>
    /// Makes the account, audited as an account created by whoever the host acts for. Refused when the username isn't
    /// one or is taken.
    /// </summary>
    Task<AccountInfo> CreateAsync(ServiceAccountInput input, CancellationToken cancellationToken = default);

    /// <summary>
    /// Makes a token for an active service account (not an agent's, which holds none), audited as made by whoever the
    /// host acts for, as an admin's is. The host decides who may ask. Refused like the admin page's: a bad name, access,
    /// lifetime, resource or tool.
    /// </summary>
    Task<NewServiceAccountToken> CreateTokenAsync(ServiceAccountTokenInput input, CancellationToken cancellationToken = default);

    /// <summary>The service account's tokens, newest first; only live ones unless <paramref name="all"/>.</summary>
    Task<IReadOnlyList<ServiceAccountTokenInfo>> ListTokensAsync(Guid accountId, bool all = false, CancellationToken cancellationToken = default);

    /// <summary>Revokes one of the service account's tokens; it stops working at once. Audited as the host's actor's.</summary>
    Task RevokeTokenAsync(Guid accountId, Guid tokenId, CancellationToken cancellationToken = default);
}
