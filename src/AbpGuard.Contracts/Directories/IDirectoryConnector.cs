namespace AbpGuard.Directories;

/// <summary>
/// Extension point guard.directory.connector@1. A connector reads users, groups and
/// memberships from one kind of directory and checks passwords against it.
/// Guard owns ordering, caching, sync scheduling, account resolution and events.
/// </summary>
public interface IDirectoryConnector
{
    /// <summary>Directory type this connector serves, for example "ldap".</summary>
    string Type { get; }

    string DisplayName { get; }

    DirectoryCapabilities Capabilities { get; }

    /// <summary>Settings an admin fills in. Secret settings are encrypted at rest and never returned by the API.</summary>
    IReadOnlyList<DirectorySettingDefinition> Settings { get; }

    Task<ConnectorAuthResult> AuthenticateAsync(DirectoryConnectionContext context, string username, string password, CancellationToken cancellationToken);

    IAsyncEnumerable<DirectoryUserRecord> ReadUsersAsync(DirectoryConnectionContext context, CancellationToken cancellationToken);

    /// <summary>Groups with their direct members. Nested groups appear as group members.</summary>
    IAsyncEnumerable<DirectoryGroupRecord> ReadGroupsAsync(DirectoryConnectionContext context, CancellationToken cancellationToken);

    Task<ConnectionTestResult> TestAsync(DirectoryConnectionContext context, CancellationToken cancellationToken);
}

[Flags]
public enum DirectoryCapabilities
{
    None = 0,
    Authenticate = 1,
    Sync = 2,
    NestedGroups = 4,
    IncrementalSync = 8,
    Write = 16,
}

public sealed record DirectorySettingDefinition(
    string Name,
    string Label,
    bool Required = false,
    bool Secret = false,
    string? DefaultValue = null,
    string? Help = null);

/// <summary>Everything a connector needs for one directory. Secrets are already decrypted.</summary>
public sealed record DirectoryConnectionContext(
    Guid DirectoryId,
    string DirectoryName,
    IReadOnlyDictionary<string, string> Settings)
{
    public string Get(string name) =>
        Settings.TryGetValue(name, out string? value) && !string.IsNullOrEmpty(value)
            ? value
            : throw new InvalidOperationException($"Directory '{DirectoryName}' is missing setting '{name}'.");

    public string? GetOrDefault(string name, string? defaultValue = null) =>
        Settings.TryGetValue(name, out string? value) && !string.IsNullOrEmpty(value) ? value : defaultValue;
}

public sealed record DirectoryUserRecord(
    string ExternalId,
    string Username,
    string? DisplayName,
    string? Email,
    bool IsActive = true);

/// <summary>
/// A group as the directory has it. Kind is null for a security group, or "ou" for a group of everyone under an
/// organizational unit, which Guard marks so admins can tell the two apart and grant either.
/// </summary>
public sealed record DirectoryGroupRecord(
    string ExternalId,
    string Name,
    string? Description,
    IReadOnlyList<string> MemberUserExternalIds,
    IReadOnlyList<string> MemberGroupExternalIds,
    string? Kind = null);

public sealed record ConnectorAuthResult(bool Succeeded, string? ExternalId = null, string? Error = null)
{
    public static ConnectorAuthResult Success(string externalId) => new(true, externalId);
    public static ConnectorAuthResult Failed(string error) => new(false, null, error);
}

public sealed record ConnectionTestResult(bool Succeeded, string Message, int? UsersFound = null, int? GroupsFound = null);
