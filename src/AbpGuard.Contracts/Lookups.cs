namespace AbpGuard;

// Integration services other modules and plugins call. Every reference to a person or group is a GUID:
// group names are display-only, because two directories may each have a group called "admins".

/// <summary>
/// An account as other modules see it. Email is where mail goes; Language and TimeZone are the person's
/// preferences (null: the site's); MergedIntoId is the account it was merged into, if it was.
/// </summary>
public sealed record AccountInfo(Guid Id, string Username, string DisplayName, string? Email, bool IsActive, Guid DirectoryId, string? Language = null,
    string? TimeZone = null, Guid? MergedIntoId = null, bool IsService = false)
{
    /// <summary>An agent's account: a service account an automated actor works through, which holds no tokens.</summary>
    public bool IsAgent { get; init; }

    /// <summary>What the account is: <see cref="AccountKinds"/>.</summary>
    public string Kind => IsAgent ? AccountKinds.Agent : IsService ? AccountKinds.Service : AccountKinds.Person;
}

/// <summary>What an account is: a person, a service account, or an agent's account (a service account an automated actor works through).</summary>
public static class AccountKinds
{
    public const string Person = "person";
    public const string Service = "service";
    public const string Agent = "agent";
}

/// <summary>A group as other modules see it; Kind is standard, directory, ou or organization.</summary>
public sealed record GroupInfo(Guid Id, string Name, string? Description, Guid DirectoryId, string Kind = "standard");

public interface IAccountLookup
{
    Task<AccountInfo?> GetAsync(Guid accountId, CancellationToken cancellationToken = default);

    /// <summary>The accounts that exist among these ids; missing ids are left out.</summary>
    Task<IReadOnlyDictionary<Guid, AccountInfo>> GetManyAsync(IEnumerable<Guid> accountIds, CancellationToken cancellationToken = default);

    /// <summary>The account with this username; for an account that was merged, the one it was merged into.</summary>
    Task<AccountInfo?> FindByUsernameAsync(string username, CancellationToken cancellationToken = default);

    /// <summary>
    /// The active accounts with this address (any letter case): their directory's, or one they verified;
    /// usually one.
    /// </summary>
    Task<IReadOnlyList<AccountInfo>> FindByEmailAsync(string email, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AccountInfo>> SearchAsync(string text, int max = 20, CancellationToken cancellationToken = default);
}

/// <summary>Groups by id or name, for fields that hold a group (a record's assignee group).</summary>
public interface IGroupLookup
{
    /// <summary>The groups that exist among these ids; missing ids are left out.</summary>
    Task<IReadOnlyDictionary<Guid, GroupInfo>> GetManyAsync(IEnumerable<Guid> groupIds, CancellationToken cancellationToken = default);

    /// <summary>A group by id, or every group with this name (two directories may each have one).</summary>
    Task<IReadOnlyList<GroupInfo>> FindAsync(string idOrName, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<GroupInfo>> SearchAsync(string text, int max = 20, CancellationToken cancellationToken = default);
}

public interface IMembershipResolver
{
    /// <summary>True if the account is in the group directly or through nested groups.</summary>
    Task<bool> IsMemberAsync(Guid accountId, Guid groupId, CancellationToken cancellationToken = default);

    /// <summary>All groups the account belongs to, including through nesting.</summary>
    Task<IReadOnlyList<GroupInfo>> GetEffectiveGroupsAsync(Guid accountId, CancellationToken cancellationToken = default);

    /// <summary>
    /// The active accounts in a group, directly or through nested groups. The group by id or by name; a name several
    /// directories use means all of those groups. Null when there's no such group.
    /// </summary>
    Task<IReadOnlyList<Guid>?> GetEffectiveMemberIdsAsync(string groupIdOrName, CancellationToken cancellationToken = default);
}

/// <summary>
/// Lets a connector plugin read the directories of the types it serves, with decrypted settings.
/// A plugin only ever sees directories whose type matches a connector it registered.
/// </summary>
public interface IDirectoryConnectionProvider
{
    Task<IReadOnlyList<Directories.DirectoryConnectionContext>> GetConnectionsAsync(CancellationToken cancellationToken = default);
}

/// <summary>How an importer's person was matched to an account.</summary>
public sealed record ProvisionedAccount(Guid AccountId, string MatchedBy);

/// <summary>
/// For importers: find the account for a person from another system, or create a deactivated placeholder in an
/// "Imported from {source}" directory (sign-in off). If the same username later comes from a directory that ranks
/// higher, directory precedence moves the account there, keeping its id and history.
/// </summary>
public interface IAccountProvisioning
{
    /// <summary>MatchedBy is "username", "email" or "placeholder".</summary>
    Task<ProvisionedAccount> MatchOrCreatePlaceholderAsync(string source, string username, string? displayName, string? email, CancellationToken cancellationToken = default);

    /// <summary>
    /// An active person in the internal directory, found by username or made (the people a development
    /// seeder fills a site with, who show as anyone does, not as an import's placeholders). They can sign in only when
    /// given a password, of at least 10 characters; one found keeps its own. Needs the caller to be a site admin.
    /// MatchedBy is "username" or "created".
    /// </summary>
    Task<ProvisionedAccount> EnsureInternalAccountAsync(Guid callerId, string username, string displayName, string? email, string? password,
        CancellationToken cancellationToken = default);
}

public static class GuardWellKnown
{
    /// <summary>The internal admins group: its effective members are site admins.</summary>
    public static readonly Guid AdminsGroupId = Guid.Parse("00000000-0000-0000-0000-00000000a001");
}

/// <summary>
/// A scope a grant's rules also apply in: with all its rules, or with its read rules only (actions narrowed
/// to read, deny rules kept).
/// </summary>
public sealed record GrantExpansion(System.Text.Json.Nodes.JsonObject Scope, bool ReadOnly);

/// <summary>
/// Lets a module widen grants without guard knowing its model: a role granted on a project also applies to the
/// projects under it, and lets its holders read the ones above. Called for every grant each time an ability
/// is built, so answers must come from memory.
/// </summary>
public interface IGrantScopeExpander
{
    ValueTask<IReadOnlyList<GrantExpansion>> ExpandAsync(System.Text.Json.Nodes.JsonObject scope, CancellationToken cancellationToken = default);
}

/// <summary>What a grant's scope is, for people: a label, and the page where it's managed (a project's members).</summary>
public sealed record GrantScopeLabel(string Label, string? Href);

/// <summary>
/// Lets a module say what its grant scopes are (a scope key such as "project:{id}"), for lists across modules such as
/// every grant to Anonymous visitors.
/// </summary>
public interface IGrantScopeDescriber
{
    Task<IReadOnlyDictionary<string, GrantScopeLabel>> DescribeAsync(IReadOnlyCollection<string> scopeKeys, CancellationToken cancellationToken = default);
}
