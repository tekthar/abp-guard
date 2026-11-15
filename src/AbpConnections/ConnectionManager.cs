using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AbpGuard.Acting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Volo.Abp;
using Volo.Abp.DependencyInjection;
using Volo.Abp.Domain.Entities;
using Volo.Abp.EntityFrameworkCore;
using Volo.Abp.Uow;

namespace AbpConnections;

/// <summary>A kind of connection, for the form that makes one: its settings, and whether it signs in with OAuth.</summary>
public sealed record ConnectionKindView(string Type, string DisplayName, bool OAuth, List<ConnectionSetting> Settings, string? Owner);

/// <summary>A connection as admins see it: its plain settings, which secrets are set (never their values), and where it stands.</summary>
public sealed record ConnectionView(
    Guid Id, string Name, string Type, string TypeName, Guid? ScopeId, Dictionary<string, string> Settings, Dictionary<string, bool> Secrets,
    bool OAuth, bool SignedIn, string? Account, DateTime? ConnectedAt, string Status, DateTime? LastTestedAt, string? LastError, DateTime CreatedAt, DateTime UpdatedAt)
{
    /// <summary>Each person signs in with their own outside account, not once for everyone.</summary>
    public bool EachPerson { get; init; }

    /// <summary>For one each person signs in to: how many have.</summary>
    public int PeopleSignedIn { get; init; }
}

/// <summary>A connection to save. A secret left blank keeps the stored one.</summary>
public sealed record ConnectionChange(string Name, string Type, Dictionary<string, string>? Settings, Dictionary<string, string>? Secrets, bool? EachPerson = null);

/// <summary>A connection each person signs in to, as one person sees it: whether they have, as which outside account, and since when.</summary>
public sealed record PersonalConnectionView(Guid Id, string Name, string TypeName, Guid? ScopeId, bool SignedIn, string? Account, DateTime? ConnectedAt);

/// <summary>A connection as lists show it: no settings or secrets.</summary>
public sealed record ConnectionSummaryView(Guid Id, string Name, string Type, Guid? ScopeId, string Status, string? Account);

/// <summary>
/// Connections: made, changed, tested, signed in with OAuth (authorization code with PKCE) and out, once for everyone or by
/// each person with their own account, and used with a fresh access token, refreshed one at a time on any server. Secrets
/// and tokens are encrypted with Data Protection and never leave the server. Who may do what, and in which scope, is the
/// caller's to check.
/// </summary>
public class ConnectionManager(
    IUnitOfWorkManager units, IDbContextProvider<IConnectionsDbContext> tables, IConnectionKinds kinds, IDataProtectionProvider protection,
    IHttpClientFactory http, ISecurityAudit audit, IEnumerable<IConnectionUses> uses, IConnectionLocks locks, IOptions<ConnectionsOptions> options)
    : ITransientDependency
{
    private static readonly ConcurrentDictionary<Guid, SemaphoreSlim> Refreshing = new();
    private static readonly JsonSerializerOptions Json = JsonSerializerOptions.Web;

    private ConnectionsOptions O => options.Value;

    private IDataProtector Secrets => protection.CreateProtector(O.SecretsPurpose);

    private ITimeLimitedDataProtector States => protection.CreateProtector(O.SignInPurpose).ToTimeLimitedDataProtector();

    public async Task<List<ConnectionKindView>> KindsAsync(CancellationToken cancellationToken)
    {
        await using IConnectionKindsLease lease = await kinds.LeaseAsync(cancellationToken);
        return [.. lease.Items
            .Select(i => new ConnectionKindView(i.Key, i.Kind.DisplayName, i.Kind.SignsIn, [.. i.Kind.Settings], i.Owner))
            .OrderBy(t => t.DisplayName)];
    }

    public async Task<List<ConnectionView>> ListAsync(Guid? scopeId, CancellationToken cancellationToken)
    {
        List<Connection> rows = await RunAsync(db => db.Connections.AsNoTracking().Where(c => c.ScopeId == scopeId).OrderBy(c => c.Name).ToListAsync(cancellationToken),
            cancellationToken);
        await using IConnectionKindsLease lease = await kinds.LeaseAsync(cancellationToken);
        List<ConnectionView> views = [];
        foreach (Connection c in rows)
        {
            views.Add(await ViewAsync(c, Find(lease, c.Type), cancellationToken));
        }

        return views;
    }

    public async Task<ConnectionView> GetAsync(Guid id, Guid? scopeId, CancellationToken cancellationToken)
    {
        Connection connection = await LoadAsync(id, scopeId, cancellationToken);
        await using IConnectionKindsLease lease = await kinds.LeaseAsync(cancellationToken);
        return await ViewAsync(connection, Find(lease, connection.Type), cancellationToken);
    }

    /// <summary>Whether saving this sets or replaces a stored secret: a host may ask the person to prove it's them first.</summary>
    public static bool SetsSecrets(ConnectionChange change) => change.Secrets?.Values.Any(v => !string.IsNullOrEmpty(v)) == true;

    public async Task<ConnectionView> CreateAsync(ConnectionChange change, Guid? scopeId, Guid createdBy, CancellationToken cancellationToken)
    {
        await using IConnectionKindsLease lease = await kinds.LeaseAsync(cancellationToken);
        IConnectionKind kind = Find(lease, change.Type) ?? throw new UserFriendlyException($"There's no connection type '{change.Type}'.{O.MissingTypeHint}");
        bool eachPerson = EachPersonOf(kind, change.EachPerson ?? false);
        Connection connection = new(Guid.NewGuid(), RequireName(change.Name), change.Type, scopeId, createdBy)
        {
            // One each person signs in to is ready as it is: people sign in themselves when they use it.
            Status = kind.SignsIn && !eachPerson ? ConnectionStatus.NeedsSignIn : ConnectionStatus.Ready,
            EachPerson = eachPerson,
        };
        (List<string> secretsSet, _) = Apply(connection, kind, change);
        await RunAsync(async db =>
        {
            db.Connections.Add(connection);
            return await db.SaveChangesAsync(cancellationToken);
        }, cancellationToken);
        await audit.WriteAsync(ConnectionAuditTypes.Created, Target(connection), new { type = connection.Type, project = scopeId, settings = SettingsOf(connection), secrets = secretsSet, eachPerson }, cancellationToken);
        return await ViewAsync(connection, kind, cancellationToken);
    }

    public async Task<ConnectionView> UpdateAsync(Guid id, ConnectionChange change, Guid? scopeId, CancellationToken cancellationToken)
    {
        await using IConnectionKindsLease lease = await kinds.LeaseAsync(cancellationToken);
        (Connection connection, IConnectionKind kind, object details) = await RunAsync(async db =>
        {
            Connection connection = await db.Connections.FirstOrDefaultAsync(c => c.Id == id && c.ScopeId == scopeId, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Connection), id);
            if (change.Type != connection.Type)
            {
                throw new UserFriendlyException("A connection's type can't change: make a new one.");
            }

            IConnectionKind kind = Find(lease, connection.Type) ?? throw new UserFriendlyException($"The '{connection.Type}' connection type isn't available.{O.MissingTypeHint}");
            string oldName = connection.Name;
            connection.Name = RequireName(change.Name);
            (List<string> secretsReplaced, Dictionary<string, (string? Before, string? After)> settingsChanged) = Apply(connection, kind, change);
            if (settingsChanged.Count > 0 || secretsReplaced.Count > 0)
            {
                // Where it signs in, and as which client, is found again for the settings it has now.
                connection.ProtectedSignIn = null;
            }

            bool? eachPersonChanged = null;
            if (change.EachPerson is { } eachPerson && EachPersonOf(kind, eachPerson) != connection.EachPerson)
            {
                // Switching either way ends every sign-in it had: one for everyone, or each person's own.
                connection.EachPerson = eachPerson;
                connection.ProtectedTokens = null;
                connection.Account = null;
                connection.ConnectedAt = null;
                connection.Status = eachPerson ? ConnectionStatus.Ready : ConnectionStatus.NeedsSignIn;
                await db.ConnectionAccounts.Where(a => a.ConnectionId == id).ExecuteDeleteAsync(cancellationToken);
                eachPersonChanged = eachPerson;
            }

            connection.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            object details = new
            {
                name = oldName == connection.Name ? null : new { before = oldName, after = connection.Name },
                settings = settingsChanged.ToDictionary(kv => kv.Key, kv => new { before = kv.Value.Before, after = kv.Value.After }),
                secrets = secretsReplaced,
                eachPerson = eachPersonChanged,
            };
            return (connection, kind, details);
        }, cancellationToken);
        await audit.WriteAsync(ConnectionAuditTypes.Updated, Target(connection), details, cancellationToken);
        return await ViewAsync(connection, kind, cancellationToken);
    }

    public async Task DeleteAsync(Guid id, Guid? scopeId, CancellationToken cancellationToken)
    {
        Connection connection = await LoadAsync(id, scopeId, cancellationToken);
        List<string> inUse = [];
        foreach (IConnectionUses use in uses)
        {
            inUse.AddRange(await use.UsesAsync(id, cancellationToken));
        }

        if (inUse.Count > 0)
        {
            throw new UserFriendlyException($"{connection.Name} is in use: {string.Join(", ", inUse)}. Stop using it first.");
        }

        await RunAsync(async db =>
        {
            await db.ConnectionAccounts.Where(a => a.ConnectionId == id).ExecuteDeleteAsync(cancellationToken);
            return await db.Connections.Where(c => c.Id == id).ExecuteDeleteAsync(cancellationToken);
        }, cancellationToken);
        await audit.WriteAsync(ConnectionAuditTypes.Deleted, Target(connection), new { type = connection.Type, project = connection.ScopeId }, cancellationToken);
    }

    /// <summary>Tries the connection with what it has (refreshing its token first when it must), and keeps the outcome.</summary>
    public async Task<ConnectionView> TestAsync(Guid id, Guid? scopeId, CancellationToken cancellationToken, Guid? accountId = null)
    {
        Connection loaded = await LoadAsync(id, scopeId, cancellationToken);
        await using IConnectionKindsLease lease = await kinds.LeaseAsync(cancellationToken);
        ConnectionTestResult result;
        IConnectionKind? kind = null;
        try
        {
            // One each person signs in to is tried with the sign-in of whoever tries it.
            ConnectionInUse context = (loaded.EachPerson
                ? accountId is { } person ? await PersonContextAsync(id, person, cancellationToken) : null
                : await ContextAsync(id, lease, cancellationToken)) ?? throw new UserFriendlyException(loaded.EachPerson
                    ? $"Each person signs in to {loaded.Name} themselves: sign in from {O.WherePeopleSignIn} to try it."
                    : "There's no such connection.");
            kind = Find(lease, context.Type) ?? throw new UserFriendlyException($"The '{context.Type}' connection type isn't available.");
            if (kind.SignsIn && context.AccessToken is null)
            {
                result = new ConnectionTestResult(false, "It hasn't signed in yet: sign it in first.");
            }
            else
            {
                using HttpClient client = http.CreateClient(O.HttpClientName);
                result = await kind.TestAsync(context, client, cancellationToken);
            }
        }
        catch (Exception ex) when (ex is UserFriendlyException or HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            result = new ConnectionTestResult(false, ex.Message);
        }

        Connection connection = await RunAsync(async db =>
        {
            Connection connection = await db.Connections.FirstAsync(c => c.Id == id, cancellationToken);
            connection.LastTestedAt = DateTime.UtcNow;
            connection.LastError = result.Succeeded ? null : result.Message;
            if (result.Succeeded)
            {
                connection.Status = ConnectionStatus.Ready;
                connection.Account = connection.EachPerson ? null : result.Account ?? connection.Account;
            }
            else if (connection.Status != ConnectionStatus.NeedsSignIn)
            {
                connection.Status = ConnectionStatus.Failing;
            }

            await db.SaveChangesAsync(cancellationToken);
            return connection;
        }, cancellationToken);
        return await ViewAsync(connection, kind ?? Find(lease, connection.Type), cancellationToken);
    }

    /// <summary>
    /// Where to send the browser to sign the connection in: the provider's authorize address with a PKCE challenge and a
    /// state that only this server can read, holding the connection, the person, the verifier and the redirect.
    /// </summary>
    public async Task<string> AuthorizeAsync(Guid id, Guid? scopeId, string redirectUri, Guid accountId, CancellationToken cancellationToken, bool personal = false)
    {
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out Uri? redirect) || redirect.Scheme is not ("http" or "https")
            || !redirect.AbsolutePath.EndsWith(O.CallbackPath, StringComparison.Ordinal))
        {
            throw new UserFriendlyException($"The redirect is the web app's {O.CallbackPath}.");
        }

        Connection connection = await LoadAsync(id, scopeId, cancellationToken);
        if (connection.EachPerson != personal)
        {
            throw new UserFriendlyException(connection.EachPerson
                ? $"Each person signs in to {connection.Name} themselves, from {O.WherePeopleSignIn}."
                : $"{connection.Name} signs in once for everyone: its admins sign it in.");
        }

        await PrepareAsync(connection, redirectUri, cancellationToken);
        ConnectionOAuthSetup oauth = await OAuthAsync(connection, cancellationToken)
            ?? throw new UserFriendlyException($"{connection.Name} doesn't sign in with OAuth.");
        string verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        string challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        string state = States.Protect(JsonSerializer.Serialize(new SignInState(connection.Id, accountId, verifier, redirectUri, personal), Json), O.SignInTime);
        Dictionary<string, string> query = new()
        {
            ["response_type"] = "code",
            ["client_id"] = oauth.ClientId,
            ["redirect_uri"] = redirectUri,
            ["state"] = state,
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        };
        if (oauth.Scopes.Count > 0)
        {
            query["scope"] = string.Join(' ', oauth.Scopes);
        }
        foreach ((string name, string value) in oauth.Extra ?? new Dictionary<string, string>())
        {
            query.TryAdd(name, value);
        }

        return oauth.AuthorizeUrl + (oauth.AuthorizeUrl.Contains('?') ? "&" : "?")
            + string.Join('&', query.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
    }

    /// <summary>Finishes a sign-in the same person started: the code for tokens (with the verifier), kept encrypted.</summary>
    public async Task<ConnectionView> CompleteAsync(string? code, string? signInState, Guid accountId, CancellationToken cancellationToken)
    {
        SignInState? state;
        try
        {
            state = JsonSerializer.Deserialize<SignInState>(States.Unprotect(signInState ?? ""), Json);
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or FormatException)
        {
            state = null;
        }

        if (state is null || state.Account != accountId)
        {
            throw new UserFriendlyException("This sign-in took too long, or someone else started it. Start it again.");
        }

        Connection connection = await RunAsync(async db => await db.Connections.AsNoTracking().FirstOrDefaultAsync(c => c.Id == state.Connection, cancellationToken)
            ?? throw new EntityNotFoundException(typeof(Connection), state.Connection), cancellationToken);
        if (connection.EachPerson != state.Personal)
        {
            throw new UserFriendlyException($"{connection.Name} changed how it signs in meanwhile. Start again.");
        }

        ConnectionOAuthSetup oauth = await OAuthAsync(connection, cancellationToken) ?? throw new UserFriendlyException($"{connection.Name} doesn't sign in with OAuth.");
        Tokens tokens = await RequestTokensAsync(oauth, new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code ?? "",
            ["redirect_uri"] = state.Redirect,
            ["code_verifier"] = state.Verifier,
        }, previousRefresh: null, cancellationToken);
        if (state.Personal)
        {
            // The person's own: kept for them alone, and the connection itself doesn't change.
            await RunAsync(async db =>
            {
                ConnectionAccount? mine = await db.ConnectionAccounts.FirstOrDefaultAsync(a => a.ConnectionId == connection.Id && a.AccountId == accountId, cancellationToken);
                if (mine is null)
                {
                    db.ConnectionAccounts.Add(mine = new ConnectionAccount(connection.Id, accountId));
                }

                mine.ProtectedTokens = Secrets.Protect(JsonSerializer.Serialize(tokens, Json));
                mine.Account = tokens.Account;
                mine.ConnectedAt = DateTime.UtcNow;
                return await db.SaveChangesAsync(cancellationToken);
            }, cancellationToken);
            await audit.WriteAsync(ConnectionAuditTypes.PersonSignedIn, Target(connection), new { account = tokens.Account }, cancellationToken);
            await using IConnectionKindsLease types = await kinds.LeaseAsync(cancellationToken);
            return await ViewAsync(connection, Find(types, connection.Type), cancellationToken);
        }

        await RunAsync(async db =>
        {
            Connection tracked = await db.Connections.FirstAsync(c => c.Id == connection.Id, cancellationToken);
            tracked.ProtectedTokens = Secrets.Protect(JsonSerializer.Serialize(tokens, Json));
            tracked.ConnectedAt = DateTime.UtcNow;
            tracked.Status = ConnectionStatus.Ready;
            tracked.LastError = null;
            tracked.Account = tokens.Account;
            tracked.UpdatedAt = DateTime.UtcNow;
            return await db.SaveChangesAsync(cancellationToken);
        }, cancellationToken);

        // The outside account it signed in as, when its type can tell (a test).
        ConnectionView view = await TestAsync(connection.Id, connection.ScopeId, cancellationToken);
        await audit.WriteAsync(ConnectionAuditTypes.SignedIn, Target(connection), new { account = view.Account }, cancellationToken);
        return view;
    }

    /// <summary>Forgets the connection's tokens: it must sign in again before it's used.</summary>
    public async Task<ConnectionView> SignOutAsync(Guid id, Guid? scopeId, CancellationToken cancellationToken)
    {
        await LoadAsync(id, scopeId, cancellationToken);
        (Connection connection, string? account) = await RunAsync(async db =>
        {
            Connection connection = await db.Connections.FirstAsync(c => c.Id == id, cancellationToken);
            string? account = connection.Account;
            connection.ProtectedTokens = null;
            connection.ConnectedAt = null;
            connection.Account = null;
            connection.Status = ConnectionStatus.NeedsSignIn;
            connection.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            return (connection, account);
        }, cancellationToken);
        await audit.WriteAsync(ConnectionAuditTypes.SignedOut, Target(connection), new { account }, cancellationToken);
        await using IConnectionKindsLease lease = await kinds.LeaseAsync(cancellationToken);
        return await ViewAsync(connection, Find(lease, connection.Type), cancellationToken);
    }

    /// <summary>Forgets one person's own sign-in to a connection each person signs in to; nothing when they had none.</summary>
    public async Task SignOutPersonAsync(Guid id, Guid accountId, CancellationToken cancellationToken)
    {
        (Connection connection, string? account, int removed) = await RunAsync(async db =>
        {
            Connection connection = await db.Connections.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Connection), id);
            string? account = await db.ConnectionAccounts.Where(a => a.ConnectionId == id && a.AccountId == accountId).Select(a => a.Account).FirstOrDefaultAsync(cancellationToken);
            int removed = await db.ConnectionAccounts.Where(a => a.ConnectionId == id && a.AccountId == accountId).ExecuteDeleteAsync(cancellationToken);
            return (connection, account, removed);
        }, cancellationToken);
        if (removed > 0)
        {
            await audit.WriteAsync(ConnectionAuditTypes.PersonSignedOut, Target(connection), new { account }, cancellationToken);
        }
    }

    /// <summary>
    /// The connections each person signs in to that a person may use (the site's, and these scopes'), with whether they
    /// have and as whom.
    /// </summary>
    public async Task<List<PersonalConnectionView>> PersonalListAsync(Guid accountId, IReadOnlyCollection<Guid> scopeIds, CancellationToken cancellationToken)
    {
        List<Guid> scopes = [.. scopeIds];
        (List<Connection> rows, Dictionary<Guid, ConnectionAccount> mine) = await RunAsync(async db =>
        {
            List<Connection> rows = await db.Connections.AsNoTracking()
                .Where(c => c.EachPerson && (c.ScopeId == null || scopes.Contains(c.ScopeId.Value))).OrderBy(c => c.ScopeId != null).ThenBy(c => c.Name)
                .ToListAsync(cancellationToken);
            List<Guid> ids = [.. rows.Select(c => c.Id)];
            Dictionary<Guid, ConnectionAccount> mine = await db.ConnectionAccounts.AsNoTracking().Where(a => a.AccountId == accountId && ids.Contains(a.ConnectionId))
                .ToDictionaryAsync(a => a.ConnectionId, cancellationToken);
            return (rows, mine);
        }, cancellationToken);
        await using IConnectionKindsLease lease = await kinds.LeaseAsync(cancellationToken);
        return [.. rows.Select(c => new PersonalConnectionView(c.Id, c.Name, Find(lease, c.Type)?.DisplayName ?? c.Type, c.ScopeId, mine.ContainsKey(c.Id),
            mine.GetValueOrDefault(c.Id)?.Account, mine.GetValueOrDefault(c.Id)?.ConnectedAt))];
    }

    /// <summary>
    /// The connection for use as one person: one each person signs in to with their own token (refreshed first when it's
    /// about to expire), any other as it is. Refused, saying how to sign in, when they haven't.
    /// </summary>
    public async Task<ConnectionInUse> ForPersonAsync(Guid id, Guid accountId, CancellationToken cancellationToken)
    {
        await using IConnectionKindsLease lease = await kinds.LeaseAsync(cancellationToken);
        Connection connection = await LoadAnyAsync(id, cancellationToken);
        return connection.EachPerson
            ? await PersonContextAsync(id, accountId, cancellationToken)
                ?? throw new PersonNotSignedInException(connection.Id, connection.Name,
                    $"You haven't signed in to {connection.Name}: sign in from {O.WherePeopleSignIn}, then ask again.")
            : await ContextAsync(id, lease, cancellationToken) ?? throw new EntityNotFoundException(typeof(Connection), id);
    }

    /// <summary>The connection for use: settings, secrets and an access token refreshed first when it's about to expire; null when there's none.</summary>
    public async Task<ConnectionInUse?> GetForUseAsync(Guid id, CancellationToken cancellationToken)
    {
        await using IConnectionKindsLease lease = await kinds.LeaseAsync(cancellationToken);
        return await ContextAsync(id, lease, cancellationToken);
    }

    /// <summary>Connections of a type, at site scope and in this scope (when one is given).</summary>
    public Task<List<ConnectionSummaryView>> ListOfTypeAsync(string type, Guid? scopeId, CancellationToken cancellationToken) => RunAsync(db =>
        db.Connections.AsNoTracking().Where(c => c.Type == type && (c.ScopeId == null || c.ScopeId == scopeId)).OrderBy(c => c.Name)
            .Select(c => new ConnectionSummaryView(c.Id, c.Name, c.Type, c.ScopeId, c.Status, c.Account)).ToListAsync(cancellationToken), cancellationToken);

    /// <summary>A connection by id, whatever its scope: for a caller that checks where it may be used.</summary>
    public async Task<ConnectionView?> FindAsync(Guid id, CancellationToken cancellationToken)
    {
        Connection? connection = await RunAsync(db => db.Connections.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, cancellationToken), cancellationToken);
        if (connection is null)
        {
            return null;
        }

        await using IConnectionKindsLease lease = await kinds.LeaseAsync(cancellationToken);
        return await ViewAsync(connection, Find(lease, connection.Type), cancellationToken);
    }

    /// <summary>The connections that sign in, at site scope and in this scope.</summary>
    public async Task<List<ConnectionView>> SigningInAsync(Guid scopeId, CancellationToken cancellationToken)
    {
        List<Connection> rows = await RunAsync(db => db.Connections.AsNoTracking().Where(c => c.ScopeId == null || c.ScopeId == scopeId).OrderBy(c => c.Name)
            .ToListAsync(cancellationToken), cancellationToken);
        await using IConnectionKindsLease lease = await kinds.LeaseAsync(cancellationToken);
        List<ConnectionView> views = [];
        foreach (Connection c in rows)
        {
            ConnectionView view = await ViewAsync(c, Find(lease, c.Type), cancellationToken);
            if (view.OAuth)
            {
                views.Add(view);
            }
        }

        return views;
    }

    /// <summary>A connection's plain settings.</summary>
    public static Dictionary<string, string> SettingsOf(Connection c) => JsonSerializer.Deserialize<Dictionary<string, string>>(c.SettingsJson, Json) ?? [];

    /// <summary>
    /// The account an ID token names (its email, or the name it signed in with), when the token endpoint sent one with an
    /// OpenID scope. It came straight from the token endpoint over TLS, so its claims are read as they are.
    /// </summary>
    public static string? AccountOf(string? idToken)
    {
        string[] parts = idToken?.Split('.') ?? [];
        if (parts.Length < 2)
        {
            return null;
        }

        try
        {
            string payload = parts[1].Replace('-', '+').Replace('_', '/');
            payload = payload.PadRight(payload.Length + ((4 - (payload.Length % 4)) % 4), '=');
            JsonNode? claims = JsonNode.Parse(Convert.FromBase64String(payload));
            return claims?["email"]?.GetValue<string>() ?? claims?["preferred_username"]?.GetValue<string>() ?? claims?["upn"]?.GetValue<string>();
        }
        catch (Exception ex) when (ex is FormatException or JsonException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>The person's own context for a connection each person signs in to; null when they haven't signed in.</summary>
    private async Task<ConnectionInUse?> PersonContextAsync(Guid id, Guid accountId, CancellationToken cancellationToken)
    {
        (Connection connection, ConnectionAccount? mine) = await RunAsync(async db =>
        {
            Connection connection = await db.Connections.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, cancellationToken) ?? throw new EntityNotFoundException(typeof(Connection), id);
            ConnectionAccount? mine = await db.ConnectionAccounts.AsNoTracking().FirstOrDefaultAsync(a => a.ConnectionId == id && a.AccountId == accountId, cancellationToken);
            return (connection, mine);
        }, cancellationToken);
        if (mine is null)
        {
            return null;
        }

        Tokens tokens = JsonSerializer.Deserialize<Tokens>(Secrets.Unprotect(mine.ProtectedTokens), Json)!;
        if (tokens.ExpiresAt is { } expires && DateTimeOffset.FromUnixTimeSeconds(expires) <= DateTimeOffset.UtcNow.AddSeconds(60))
        {
            tokens = await RefreshPersonAsync(connection, accountId, cancellationToken);
        }

        return new ConnectionInUse(connection.Id, connection.Name, connection.Type, connection.ScopeId, SettingsOf(connection), SecretsOf(connection), tokens.Access,
            mine.Account);
    }

    /// <summary>
    /// A person's new access token from their refresh token, one at a time for each person and connection on any server. A
    /// refused refresh ends their sign-in (they sign in again); one the provider didn't answer keeps it.
    /// </summary>
    private async Task<Tokens> RefreshPersonAsync(Connection connection, Guid accountId, CancellationToken cancellationToken)
    {
        SemaphoreSlim gate = Refreshing.GetOrAdd(PersonGate(connection.Id, accountId), _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        try
        {
            await using IAsyncDisposable held = await locks.TakeAsync($"connection-refresh:{connection.Id}:{accountId}", cancellationToken);
            using IUnitOfWork uow = units.Begin(requiresNew: true);
            IConnectionsDbContext db = await tables.GetDbContextAsync();
            ConnectionAccount mine = await db.ConnectionAccounts.FirstOrDefaultAsync(a => a.ConnectionId == connection.Id && a.AccountId == accountId, cancellationToken)
                ?? throw new PersonNotSignedInException(connection.Id, connection.Name, $"You must sign in to {connection.Name} again.");
            Tokens tokens = JsonSerializer.Deserialize<Tokens>(Secrets.Unprotect(mine.ProtectedTokens), Json)!;
            if (tokens.ExpiresAt is not { } expires || DateTimeOffset.FromUnixTimeSeconds(expires) > DateTimeOffset.UtcNow.AddSeconds(60))
            {
                return tokens; // refreshed by another caller while this one waited
            }

            ConnectionOAuthSetup oauth = await OAuthAsync(connection, cancellationToken) ?? throw new UserFriendlyException($"{connection.Name} doesn't sign in with OAuth.");
            string? why = tokens.Refresh is null ? "Your sign-in expired and there's no refresh token." : null;
            if (why is null)
            {
                try
                {
                    Tokens fresh = await RequestTokensAsync(oauth, new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = tokens.Refresh! },
                        tokens.Refresh, cancellationToken);
                    mine.ProtectedTokens = Secrets.Protect(JsonSerializer.Serialize(fresh, Json));
                    await db.SaveChangesAsync(cancellationToken);
                    await uow.CompleteAsync(cancellationToken);
                    return fresh;
                }
                catch (UserFriendlyException ex) when (ex is not ProviderUnreachableException)
                {
                    why = ex.Message;
                }
            }

            db.ConnectionAccounts.Remove(mine);
            await db.SaveChangesAsync(cancellationToken);
            await uow.CompleteAsync(cancellationToken);
            throw new PersonNotSignedInException(connection.Id, connection.Name, $"You must sign in to {connection.Name} again: {why}");
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>A gate's key for one person's refreshes, apart from the connection's own.</summary>
    private static Guid PersonGate(Guid connectionId, Guid accountId)
    {
        byte[] a = connectionId.ToByteArray(), b = accountId.ToByteArray();
        for (int i = 0; i < a.Length; i++)
        {
            a[i] ^= (byte)(b[i] ^ 0x5A);
        }

        return new Guid(a);
    }

    /// <summary>What a kind that must find out how to sign in finds, kept for its next sign-ins.</summary>
    private async Task PrepareAsync(Connection connection, string redirectUri, CancellationToken cancellationToken)
    {
        IConnectionSignInPreparer? preparer;
        await using (IConnectionKindsLease lease = await kinds.LeaseAsync(cancellationToken))
        {
            preparer = Find(lease, connection.Type) as IConnectionSignInPreparer;
        }

        if (preparer is null)
        {
            return;
        }

        ConnectionInUse context = new(connection.Id, connection.Name, connection.Type, connection.ScopeId, SettingsOf(connection), SecretsOf(connection), null, null);
        Dictionary<string, string>? found = await preparer.PrepareAsync(context, FoundOf(connection), redirectUri, cancellationToken);
        if (found is null)
        {
            return;
        }

        string kept = Secrets.Protect(JsonSerializer.Serialize(found, Json));
        await RunAsync(db => db.Connections.Where(c => c.Id == connection.Id).ExecuteUpdateAsync(s => s.SetProperty(c => c.ProtectedSignIn, kept), cancellationToken),
            cancellationToken);
        connection.ProtectedSignIn = kept;
    }

    private Dictionary<string, string> FoundOf(Connection c) =>
        c.ProtectedSignIn is null ? [] : JsonSerializer.Deserialize<Dictionary<string, string>>(Secrets.Unprotect(c.ProtectedSignIn), Json) ?? [];

    private Task<Connection> LoadAnyAsync(Guid id, CancellationToken cancellationToken) =>
        RunAsync(async db => await db.Connections.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, cancellationToken)
            ?? throw new EntityNotFoundException(typeof(Connection), id), cancellationToken);

    /// <summary>Only a connection that signs in can have each person sign in; any other is one for everyone.</summary>
    private static bool EachPersonOf(IConnectionKind kind, bool wanted) =>
        wanted && (kind.SignsIn ? true : throw new UserFriendlyException($"{kind.DisplayName} connections don't sign in, so each person can't sign in to one."));

    /// <summary>The connection for use: settings, secrets and an access token refreshed first when it's about to expire.</summary>
    private async Task<ConnectionInUse?> ContextAsync(Guid id, IConnectionKindsLease lease, CancellationToken cancellationToken)
    {
        Connection? connection = await RunAsync(db => db.Connections.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, cancellationToken), cancellationToken);
        if (connection is null)
        {
            return null;
        }

        Dictionary<string, string> secrets = SecretsOf(connection);
        string? accessToken = null;
        if (connection.ProtectedTokens is not null)
        {
            Tokens tokens = TokensOf(connection);
            if (tokens.ExpiresAt is { } expires && DateTimeOffset.FromUnixTimeSeconds(expires) <= DateTimeOffset.UtcNow.AddSeconds(60))
            {
                _ = Find(lease, connection.Type) ?? throw new UserFriendlyException($"The '{connection.Type}' connection type isn't available.");
                tokens = await RefreshAsync(connection.Id, cancellationToken);
            }

            accessToken = tokens.Access;
        }

        return new ConnectionInUse(connection.Id, connection.Name, connection.Type, connection.ScopeId, SettingsOf(connection), secrets, accessToken, connection.Account);
    }

    /// <summary>
    /// A new access token from the refresh token, one refresh at a time for each connection, on any server: whoever
    /// waited reads the tokens the first one stored. A refused refresh means it must sign in again, so two servers
    /// refreshing at once with a token the provider replaces on use would end the sign-in.
    /// </summary>
    private async Task<Tokens> RefreshAsync(Guid id, CancellationToken cancellationToken)
    {
        SemaphoreSlim gate = Refreshing.GetOrAdd(id, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        try
        {
            await using IAsyncDisposable held = await locks.TakeAsync($"connection-refresh:{id}", cancellationToken);
            using IUnitOfWork uow = units.Begin(requiresNew: true);
            IConnectionsDbContext db = await tables.GetDbContextAsync();
            Connection connection = await db.Connections.FirstAsync(c => c.Id == id, cancellationToken);
            if (connection.ProtectedTokens is null)
            {
                throw new UserFriendlyException($"{connection.Name} must sign in again.");
            }

            Tokens tokens = TokensOf(connection);
            if (tokens.ExpiresAt is not { } expires || DateTimeOffset.FromUnixTimeSeconds(expires) > DateTimeOffset.UtcNow.AddSeconds(60))
            {
                return tokens; // another caller refreshed it while this one waited
            }

            ConnectionOAuthSetup oauth = await OAuthAsync(connection, cancellationToken) ?? throw new UserFriendlyException($"{connection.Name} doesn't sign in with OAuth.");
            if (tokens.Refresh is null)
            {
                return await SignInAgainAsync(db, uow, connection, "Its sign-in expired and there's no refresh token.", cancellationToken);
            }

            try
            {
                Tokens fresh = await RequestTokensAsync(oauth, new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = tokens.Refresh }, tokens.Refresh, cancellationToken);
                connection.ProtectedTokens = Secrets.Protect(JsonSerializer.Serialize(fresh, Json));
                await db.SaveChangesAsync(cancellationToken);
                await uow.CompleteAsync(cancellationToken);
                return fresh;
            }
            catch (UserFriendlyException ex) when (ex is not ProviderUnreachableException)
            {
                // The provider said no: the sign-in is over. One that didn't answer may yet, so the tokens stay.
                return await SignInAgainAsync(db, uow, connection, ex.Message, cancellationToken);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    private static async Task<Tokens> SignInAgainAsync(IConnectionsDbContext db, IUnitOfWork uow, Connection connection, string why, CancellationToken cancellationToken)
    {
        connection.ProtectedTokens = null;
        connection.Status = ConnectionStatus.NeedsSignIn;
        connection.LastError = why;
        connection.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        await uow.CompleteAsync(cancellationToken);
        throw new UserFriendlyException($"{connection.Name} must sign in again: {why}");
    }

    private async Task<Tokens> RequestTokensAsync(ConnectionOAuthSetup oauth, Dictionary<string, string> form, string? previousRefresh, CancellationToken cancellationToken)
    {
        form["client_id"] = oauth.ClientId;
        if (!string.IsNullOrEmpty(oauth.ClientSecret))
        {
            form["client_secret"] = oauth.ClientSecret; // a public client (PKCE alone) sends none
        }

        if (oauth.Extra?.GetValueOrDefault("resource") is { Length: > 0 } resource)
        {
            form["resource"] = resource; // the server the token is for (RFC 8707), as the authorization named it
        }
        using HttpClient client = http.CreateClient(O.HttpClientName);
        using HttpRequestMessage request = new(HttpMethod.Post, oauth.TokenUrl) { Content = new FormUrlEncodedContent(form) };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        HttpResponseMessage response;
        string body;
        try
        {
            response = await client.SendAsync(request, cancellationToken);
            body = await response.Content.ReadAsStringAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            throw new ProviderUnreachableException($"The provider didn't answer: {ex.Message}");
        }

        using HttpResponseMessage answered = response;
        JsonObject? json = null;
        try
        {
            json = JsonNode.Parse(body) as JsonObject;
        }
        catch (JsonException)
        {
            // not JSON: said below
        }

        if (!response.IsSuccessStatusCode || json?["access_token"]?.GetValue<string>() is not { Length: > 0 } access)
        {
            string why = json?["error_description"]?.GetValue<string>() ?? json?["error"]?.GetValue<string>() ?? $"{(int)response.StatusCode} {response.ReasonPhrase}";
            throw new UserFriendlyException($"The provider refused: {why}");
        }

        long? expiresAt = json["expires_in"] is { } expiresIn && long.TryParse(expiresIn.ToString(), out long seconds)
            ? DateTimeOffset.UtcNow.AddSeconds(seconds).ToUnixTimeSeconds()
            : null;
        return new Tokens(access, json["refresh_token"]?.GetValue<string>() ?? previousRefresh, expiresAt, AccountOf(json["id_token"]?.GetValue<string>()));
    }

    private async Task<ConnectionOAuthSetup?> OAuthAsync(Connection connection, CancellationToken cancellationToken)
    {
        await using IConnectionKindsLease lease = await kinds.LeaseAsync(cancellationToken);
        IConnectionKind kind = Find(lease, connection.Type) ?? throw new UserFriendlyException($"The '{connection.Type}' connection type isn't available.");
        Dictionary<string, string> settings = SettingsOf(connection), secrets = SecretsOf(connection);
        // What its sign-in found (an MCP server's endpoints and the client registered there), under "_" names.
        foreach ((string name, string value) in FoundOf(connection))
        {
            (name.EndsWith("_secret", StringComparison.Ordinal) ? secrets : settings)[name] = value;
        }

        return kind.OAuth(settings, secrets);
    }

    private Task<Connection> LoadAsync(Guid id, Guid? scopeId, CancellationToken cancellationToken) =>
        RunAsync(async db => await db.Connections.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id && c.ScopeId == scopeId, cancellationToken)
            ?? throw new EntityNotFoundException(typeof(Connection), id), cancellationToken);

    /// <summary>
    /// Applies the change's settings and secrets as the kind defines them: required ones are needed, a blank secret keeps
    /// the stored one. Returns the secrets set or replaced (names only) and the settings that changed.
    /// </summary>
    private (List<string> Secrets, Dictionary<string, (string? Before, string? After)> Settings) Apply(Connection connection, IConnectionKind kind, ConnectionChange change)
    {
        Dictionary<string, string> storedSettings = SettingsOf(connection);
        Dictionary<string, string> storedSecrets = SecretsOf(connection);
        Dictionary<string, string> settings = [];
        Dictionary<string, string> secrets = [];
        foreach (ConnectionSetting definition in kind.Settings)
        {
            if (definition.Secret)
            {
                string? value = change.Secrets?.GetValueOrDefault(definition.Name);
                value = string.IsNullOrEmpty(value) ? storedSecrets.GetValueOrDefault(definition.Name) : value;
                if (!string.IsNullOrEmpty(value))
                {
                    secrets[definition.Name] = value;
                }
            }
            else
            {
                string? value = change.Settings?.GetValueOrDefault(definition.Name)?.Trim();
                value = string.IsNullOrEmpty(value) ? definition.DefaultValue : value;
                if (!string.IsNullOrEmpty(value))
                {
                    settings[definition.Name] = value;
                }
            }

            if (definition.Required && string.IsNullOrEmpty(definition.Secret ? secrets.GetValueOrDefault(definition.Name) : settings.GetValueOrDefault(definition.Name)))
            {
                throw new UserFriendlyException($"'{definition.Label}' is required.");
            }
        }

        connection.SettingsJson = JsonSerializer.Serialize(settings, Json);
        connection.ProtectedSecrets = secrets.Count == 0 ? null : Secrets.Protect(JsonSerializer.Serialize(secrets, Json));
        List<string> secretsChanged = secrets.Keys.Union(storedSecrets.Keys).Where(k => secrets.GetValueOrDefault(k) != storedSecrets.GetValueOrDefault(k)).Order().ToList();
        Dictionary<string, (string?, string?)> settingsChanged = settings.Keys.Union(storedSettings.Keys)
            .Where(k => settings.GetValueOrDefault(k) != storedSettings.GetValueOrDefault(k))
            .ToDictionary(k => k, k => ((string?)storedSettings.GetValueOrDefault(k), (string?)settings.GetValueOrDefault(k)));
        return (secretsChanged, settingsChanged);
    }

    private async Task<ConnectionView> ViewAsync(Connection c, IConnectionKind? kind, CancellationToken cancellationToken)
    {
        Dictionary<string, string> settings = SettingsOf(c);
        Dictionary<string, string> secrets = SecretsOf(c);
        bool oauth = kind?.SignsIn == true;
        // How many people signed in to one each person signs in to; counted when it's shown, as there are few.
        int people = c.EachPerson ? await RunAsync(db => db.ConnectionAccounts.CountAsync(a => a.ConnectionId == c.Id, cancellationToken), cancellationToken) : 0;
        return new ConnectionView(c.Id, c.Name, c.Type, kind?.DisplayName ?? c.Type, c.ScopeId, settings,
            (kind?.Settings ?? []).Where(d => d.Secret).ToDictionary(d => d.Name, d => secrets.ContainsKey(d.Name)),
            oauth, c.ProtectedTokens is not null, c.Account, c.ConnectedAt, c.Status,
            c.LastTestedAt, c.LastError, c.CreatedAt, c.UpdatedAt) { EachPerson = c.EachPerson, PeopleSignedIn = people };
    }

    private Dictionary<string, string> SecretsOf(Connection c) =>
        c.ProtectedSecrets is null ? [] : JsonSerializer.Deserialize<Dictionary<string, string>>(Secrets.Unprotect(c.ProtectedSecrets), Json) ?? [];

    private Tokens TokensOf(Connection c) => JsonSerializer.Deserialize<Tokens>(Secrets.Unprotect(c.ProtectedTokens!), Json)!;

    private static AuditTarget Target(Connection c) => new("Connection", c.Id, c.Name);

    private static string RequireName(string? name) =>
        string.IsNullOrWhiteSpace(name) || name.Trim().Length > 200 ? throw new UserFriendlyException("Connection names are 1–200 characters.") : name.Trim();

    private static IConnectionKind? Find(IConnectionKindsLease lease, string key) => lease.Items.FirstOrDefault(i => i.Key == key)?.Kind;

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>One unit of work of its own: what it saves is kept when it returns.</summary>
    private async Task<T> RunAsync<T>(Func<IConnectionsDbContext, Task<T>> work, CancellationToken cancellationToken)
    {
        using IUnitOfWork uow = units.Begin(requiresNew: true);
        IConnectionsDbContext db = await tables.GetDbContextAsync();
        T result = await work(db);
        await uow.CompleteAsync(cancellationToken);
        return result;
    }

    // The shapes saved before keep their names: a sign-in's state, and the tokens kept encrypted in the tables.
    private sealed record SignInState(Guid Connection, Guid Account, string Verifier, string Redirect, bool Personal = false);

    private sealed record Tokens(string Access, string? Refresh, long? ExpiresAt, string? Account = null);
}
