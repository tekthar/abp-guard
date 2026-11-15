using Volo.Abp;

namespace AbpConnections;

/// <summary>One setting a connection type asks for: a secret is encrypted and never shown again.</summary>
public sealed record ConnectionSetting(string Name, string Label, bool Secret = false, bool Required = false, string? DefaultValue = null, string? Help = null);

/// <summary>
/// How a connection signs in with OAuth 2.0: where, and for what; Extra are parameters the provider wants on the authorize
/// address (Google's <c>access_type=offline</c>, for a refresh token, or a <c>resource</c>).
/// </summary>
public sealed record ConnectionOAuthSetup(string AuthorizeUrl, string TokenUrl, IReadOnlyList<string> Scopes, string ClientId, string ClientSecret,
    IReadOnlyDictionary<string, string>? Extra = null);

/// <summary>
/// A connection as the server uses it: its settings and secrets, and when it signs in with OAuth, a fresh access token and
/// the outside account it's for. Never sent to a browser.
/// </summary>
public sealed record ConnectionInUse(
    Guid Id, string Name, string Type, Guid? ScopeId, IReadOnlyDictionary<string, string> Settings, IReadOnlyDictionary<string, string> Secrets,
    string? AccessToken, string? Account);

/// <summary>A test's outcome: whether it worked, what to say, and the outside account it reached when it knows.</summary>
public sealed record ConnectionTestResult(bool Succeeded, string Message, string? Account = null);

/// <summary>A kind of outside system: its settings, how it signs in with OAuth when it does, and a test.</summary>
public interface IConnectionKind
{
    string Type { get; }

    string DisplayName { get; }

    IReadOnlyList<ConnectionSetting> Settings { get; }

    /// <summary>Whether it signs in to the outside system with OAuth (then <see cref="OAuth"/> says how).</summary>
    bool SignsIn { get; }

    /// <summary>How it signs in with OAuth, from its settings and secrets; null when it doesn't.</summary>
    ConnectionOAuthSetup? OAuth(IReadOnlyDictionary<string, string> settings, IReadOnlyDictionary<string, string> secrets);

    /// <summary>Tries the connection: reaches the outside system with what it has (a token, a key).</summary>
    Task<ConnectionTestResult> TestAsync(ConnectionInUse connection, HttpClient http, CancellationToken cancellationToken);
}

/// <summary>
/// A kind that must find out how to sign in before its first sign-in (an MCP server finds its authorization server and
/// registers the application there). Given what it found last time, it returns what to keep now, or null when that still
/// holds; what it keeps reaches its <see cref="IConnectionKind.OAuth"/> in the settings (and, for a name ending in
/// "_secret", the secrets) under names that start with "_".
/// </summary>
public interface IConnectionSignInPreparer
{
    Task<Dictionary<string, string>?> PrepareAsync(ConnectionInUse connection, IReadOnlyDictionary<string, string> found, string redirectUri,
        CancellationToken cancellationToken);
}

/// <summary>A kind as the application offers it: its key (what a connection's Type holds), and who added it when it's added.</summary>
public sealed record ConnectionKindEntry(string Key, IConnectionKind Kind, string? Owner);

/// <summary>The kinds offered now, held while they're used (a plugin's can't unload under it).</summary>
public interface IConnectionKindsLease : IAsyncDisposable
{
    IReadOnlyList<ConnectionKindEntry> Items { get; }
}

/// <summary>Where the kinds come from: the application's own, and what its plugins add.</summary>
public interface IConnectionKinds
{
    Task<IConnectionKindsLease> LeaseAsync(CancellationToken cancellationToken);
}

/// <summary>What uses a connection, so it can't be removed while something does (a mailbox, a repository).</summary>
public interface IConnectionUses
{
    Task<IReadOnlyList<string>> UsesAsync(Guid connectionId, CancellationToken cancellationToken);
}

/// <summary>A lock every server shares, held while a connection's token is refreshed.</summary>
public interface IConnectionLocks
{
    Task<IAsyncDisposable> TakeAsync(string name, CancellationToken cancellationToken);
}

/// <summary>How connections keep their secrets, sign in, and say where people sign in.</summary>
public sealed class ConnectionsOptions
{
    /// <summary>The Data Protection purpose secrets and tokens are protected under. Change it and every saved secret is lost.</summary>
    public string SecretsPurpose { get; set; } = "AbpConnections.Secrets.v1";

    /// <summary>The purpose a sign-in's state is protected under, for <see cref="SignInTime"/>.</summary>
    public string SignInPurpose { get; set; } = "AbpConnections.SignIn.v1";

    /// <summary>The named client the tests and the token calls use: give it the application's outbound guard.</summary>
    public string HttpClientName { get; set; } = "Connections";

    /// <summary>How long an OAuth sign-in may take, from the redirect to the provider until it comes back.</summary>
    public TimeSpan SignInTime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>The path a sign-in's redirect ends with: the application's page that finishes it.</summary>
    public string CallbackPath { get; set; } = "/connections/callback";

    /// <summary>Where a person signs in to a connection each person signs in to, as messages say it.</summary>
    public string WherePeopleSignIn { get; set; } = "the connected accounts page";

    /// <summary>Said after "There's no connection type 'x'." (a hint at why).</summary>
    public string MissingTypeHint { get; set; } = "";
}

/// <summary>What the security audit records about connections.</summary>
public static class ConnectionAuditTypes
{
    public const string Created = "connection.created";
    public const string Updated = "connection.updated";
    public const string Deleted = "connection.deleted";
    public const string SignedIn = "connection.signed-in";
    public const string SignedOut = "connection.signed-out";

    /// <summary>A person signed in with their own account to a connection each person signs in to, or out.</summary>
    public const string PersonSignedIn = "connection.person-signed-in";
    public const string PersonSignedOut = "connection.person-signed-out";
}

/// <summary>The provider didn't answer (a timeout, a refused connection): unlike a refusal, the sign-in may still be good.</summary>
public sealed class ProviderUnreachableException(string message) : UserFriendlyException(message);

/// <summary>A person hasn't signed in (or must again) to a connection each person signs in to: the message says how.</summary>
public sealed class PersonNotSignedInException(Guid connectionId, string connectionName, string message) : UserFriendlyException(message)
{
    public Guid ConnectionId { get; } = connectionId;
    public string ConnectionName { get; } = connectionName;
}
