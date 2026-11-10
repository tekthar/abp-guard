using Volo.Abp.Domain.Entities;

namespace AbpGuard.Domain;

public static class GuardRoles
{
    public static readonly Guid AdministratorId = Guid.Parse("00000000-0000-0000-0000-0000000000b1");
    public static readonly Guid DirectoryHelpdeskId = Guid.Parse("00000000-0000-0000-0000-0000000000b2");
}

/// <summary>A named set of rules in CASL's format, for example "Directory helpdesk".</summary>
public class Role : Entity<Guid>
{
    protected Role()
    {
    }

    public Role(Guid id, string key, string name, bool isSystem) : base(id)
    {
        Key = key;
        Name = name;
        IsSystem = isSystem;
    }

    public string Key { get; private set; } = null!;
    public string Name { get; set; } = null!;
    public string? Description { get; set; }
    public bool IsSystem { get; private set; }
}

/// <summary>One rule of a role, stored as CASL raw-rule JSON. Placeholders like ${grant.directoryIds} are filled per grant.</summary>
public class RoleRule : Entity<Guid>
{
    protected RoleRule()
    {
    }

    public RoleRule(Guid id, Guid roleId, int order, string json) : base(id)
    {
        RoleId = roleId;
        Order = order;
        Json = json;
    }

    public Guid RoleId { get; private set; }
    public int Order { get; set; }
    public string Json { get; set; } = null!;
}

/// <summary>Gives a role to an account or a group, with a scope that fills the role's ${grant.*} placeholders.</summary>
public class RoleGrant : Entity<Guid>
{
    protected RoleGrant()
    {
    }

    public RoleGrant(Guid id, Guid roleId, PrincipalType principalType, Guid principalId, string scopeJson) : base(id)
    {
        RoleId = roleId;
        PrincipalType = principalType;
        PrincipalId = principalId;
        ScopeJson = scopeJson;
        CreatedAt = DateTime.UtcNow;
    }

    public Guid RoleId { get; private set; }
    public PrincipalType PrincipalType { get; private set; }
    public Guid PrincipalId { get; private set; }

    /// <summary>JSON object, e.g. {"directoryIds":["..."]}. Read by rules as ${grant.directoryIds}.</summary>
    public string ScopeJson { get; set; } = "{}";

    /// <summary>
    /// What the scope is about, for listing grants without reading JSON: for example "project:{id}" for a project
    /// role. Null for grants that aren't tied to one object.
    /// </summary>
    public string? ScopeKey { get; set; }

    public DateTime? ValidUntil { get; set; }
    public DateTime CreatedAt { get; private set; }
    public Guid? CreatedBy { get; set; }
}

/// <summary>
/// One row whose version goes up, in the same transaction, with every write to what abilities are built from:
/// database triggers on those tables do it. A kept ability is used only while the version it was built under is current.
/// </summary>
public class PermissionStamp
{
    public const int RowId = 1;

    public int Id { get; set; }
    public long Version { get; set; }
}
