using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Casl;
using AbpGuard.Data;
using AbpGuard.Domain;
using AbpGuard.Acting;
using Volo.Abp;
using Volo.Abp.DependencyInjection;
using Volo.Abp.Domain.Entities;

namespace AbpGuard.Services;

/// <summary>
/// Roles and grants for other modules, behind <see cref="IRoleCatalog"/>. Projects keep
/// their roles here instead of in a second permission system: a project role is a system role whose rules use
/// ${grant.projectId}, and a member is a grant with scope {"projectId": …} and scope key "project:{id}".
/// </summary>
[ExposeServices(typeof(RoleCatalog), typeof(IRoleCatalog))]
public class RoleCatalog(GuardDb guardDb, MembershipGraph graph, SecurityLog audit, Microsoft.Extensions.Options.IOptions<GuardOptions> options)
    : ITransientDependency, IRoleCatalog
{
    public static readonly System.Text.RegularExpressions.Regex KeyPattern = RoleKeys.Pattern;

    /// <summary>Problems with one rule in CASL's raw format: subjects, fields, condition paths, operators.</summary>
    public static IReadOnlyList<string> Problems(JsonObject rule)
    {
        try
        {
            return AbilityBuilder.Validate(RawRule.Parse(rule.ToJsonString()), GuardSubjects.Registry);
        }
        catch (JsonException ex)
        {
            return [ex.Message];
        }
    }

    /// <summary>Throws unless the scope fills every ${grant.*} placeholder the rules use.</summary>
    public static void EnsureScopeFits(IEnumerable<RawRule> rules, JsonObject scope)
    {
        try
        {
            _ = new AbilityBuilder(GuardSubjects.Registry, GuardSubjects.Options)
                .WithVariables(new { user = new { id = Guid.Empty, username = "", directoryId = Guid.Empty, groupIds = Array.Empty<Guid>() } })
                .AddRange(rules, new { grant = scope })
                .Build();
        }
        catch (CaslConfigurationException ex)
        {
            throw new UserFriendlyException($"This scope doesn't fit the role's rules: {ex.Message}");
        }
    }

    /// <summary>
    /// Creates a system role, or brings its name and rules up to date. Idempotent: running it again with the same
    /// definition changes nothing. System roles can't be edited in the UI, so the code stays the source of truth.
    /// </summary>
    public Task<Guid> EnsureSystemRoleAsync(RoleDefinition definition, CancellationToken cancellationToken = default)
    {
        if (!KeyPattern.IsMatch(definition.Key))
        {
            throw new UserFriendlyException($"Role key '{definition.Key}' must be lowercase letters, digits and dashes.");
        }

        List<string> errors = definition.Rules.SelectMany((rule, i) => Problems(rule).Select(e => $"Role {definition.Key}, rule {i + 1}: {e}")).ToList();
        if (errors.Count > 0)
        {
            throw new UserFriendlyException(string.Join(" ", errors));
        }

        return guardDb.RunAsync(async db =>
        {
            Role? role = await db.Roles.FirstOrDefaultAsync(r => r.Key == definition.Key, cancellationToken);
            bool created = role is null;
            if (role is null)
            {
                role = new Role(Guid.NewGuid(), definition.Key, definition.Name, isSystem: true) { Description = definition.Description };
                db.Roles.Add(role);
            }
            else
            {
                if (!role.IsSystem)
                {
                    throw new UserFriendlyException($"A role with key '{definition.Key}' already exists and was created by an admin.");
                }

                role.Name = definition.Name;
                role.Description = definition.Description;
            }

            List<RoleRule> existing = await db.RoleRules.Where(r => r.RoleId == role.Id).OrderBy(r => r.Order).ToListAsync(cancellationToken);
            List<string> wanted = definition.Rules.Select(r => r.ToJsonString()).ToList();
            if (!existing.Select(r => r.Json).SequenceEqual(wanted, StringComparer.Ordinal)
                && !existing.Select(r => Normalize(r.Json)).SequenceEqual(wanted.Select(Normalize), StringComparer.Ordinal))
            {
                db.RoleRules.RemoveRange(existing);
                for (int i = 0; i < wanted.Count; i++)
                {
                    db.RoleRules.Add(new RoleRule(Guid.NewGuid(), role.Id, i, wanted[i]));
                }

                // A role in code changes when the host or a plugin is upgraded: what it allows changes for everyone who holds it.
                audit.Add(db, created ? SecurityAuditTypes.RoleCreated : SecurityAuditTypes.RoleUpdated, RoleTarget(role),
                    new { system = true, rules = definition.Rules, before = created ? null : existing.Select(r => JsonNode.Parse(r.Json)).ToList() });
            }

            await db.SaveChangesAsync(cancellationToken);
            return role.Id;
        }, cancellationToken: cancellationToken);
    }

    public Task<Guid?> FindRoleIdAsync(string key, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(db => db.Roles.AsNoTracking().Where(r => r.Key == key).Select(r => (Guid?)r.Id).FirstOrDefaultAsync(cancellationToken),
            cancellationToken: cancellationToken);

    /// <summary>
    /// Gives a role to an account or a group. Idempotent: the same role, principal and scope key returns the existing
    /// grant. The scope must fill every placeholder of the role's rules.
    /// </summary>
    public Task<Guid> GrantAsync(
        Guid roleId, PrincipalType principalType, Guid principalId, JsonObject scope, string? scopeKey,
        DateTime? validUntil, Guid? createdBy, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            Role role = await db.Roles.AsNoTracking().FirstOrDefaultAsync(r => r.Id == roleId, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Role), roleId);

            bool principalExists = principalType switch
            {
                PrincipalType.Account => await db.Accounts.AnyAsync(a => a.Id == principalId, cancellationToken),
                PrincipalType.Group => await db.Groups.AnyAsync(g => g.Id == principalId, cancellationToken),
                _ => principalId == GuardConstants.AnonymousId,
            };
            if (!principalExists)
            {
                throw new UserFriendlyException($"No {principalType} with id {principalId}.");
            }

            RoleGrant? same = await db.RoleGrants.FirstOrDefaultAsync(g =>
                g.RoleId == roleId && g.PrincipalType == principalType && g.PrincipalId == principalId && g.ScopeKey == scopeKey, cancellationToken);
            if (same is not null && scopeKey is not null)
            {
                return same.Id;
            }

            List<RawRule> rules = (await db.RoleRules.Where(r => r.RoleId == roleId).ToListAsync(cancellationToken)).Select(r => RawRule.Parse(r.Json)).ToList();
            EnsureScopeFits(rules, scope);

            RoleGrant grant = new(Guid.NewGuid(), roleId, principalType, principalId, scope.ToJsonString())
            {
                ScopeKey = scopeKey,
                ValidUntil = validUntil,
                CreatedBy = createdBy,
            };
            db.RoleGrants.Add(grant);
            audit.Add(db, SecurityAuditTypes.GrantAdded, await PrincipalTargetAsync(db, principalType, principalId, cancellationToken),
                GrantDetail(grant, role));
            await db.SaveChangesAsync(cancellationToken);
            return grant.Id;
        }, cancellationToken: cancellationToken);

    public Task RevokeAsync(Guid grantId, string? scopeKey = null, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            RoleGrant grant = await db.RoleGrants.FirstOrDefaultAsync(g => g.Id == grantId && (scopeKey == null || g.ScopeKey == scopeKey), cancellationToken)
                ?? throw new EntityNotFoundException(typeof(RoleGrant), grantId);
            if (grant.RoleId == GuardRoles.AdministratorId && grant.PrincipalId == GuardConstants.AdminsGroupId)
            {
                throw new UserFriendlyException($"The Administrator grant to {options.Value.AdminsGroupName} can't be revoked; manage admins through that group.");
            }

            db.RoleGrants.Remove(grant);
            Role? role = await db.Roles.AsNoTracking().FirstOrDefaultAsync(r => r.Id == grant.RoleId, cancellationToken);
            audit.Add(db, SecurityAuditTypes.GrantRemoved, await PrincipalTargetAsync(db, grant.PrincipalType, grant.PrincipalId, cancellationToken),
                GrantDetail(grant, role));
            await db.SaveChangesAsync(cancellationToken);
        }, cancellationToken: cancellationToken);

    public static AuditTarget RoleTarget(Role role) => new("Role", role.Id, role.Name);

    /// <summary>Whose rights a grant changes: the account, the group, or Anonymous visitors.</summary>
    public static async Task<AuditTarget> PrincipalTargetAsync(GuardDbContext db, PrincipalType type, Guid id, CancellationToken cancellationToken)
    {
        string? name = type switch
        {
            PrincipalType.Account => await db.Accounts.Where(a => a.Id == id).Select(a => a.Username).FirstOrDefaultAsync(cancellationToken),
            PrincipalType.Group => await db.Groups.Where(g => g.Id == id).Select(g => g.Name).FirstOrDefaultAsync(cancellationToken),
            _ => AnonymousName,
        };
        return new AuditTarget(type.ToString(), id, name);
    }

    private static object GrantDetail(RoleGrant grant, Role? role) => new
    {
        grant = grant.Id,
        role = role is null ? null : new { id = role.Id, key = role.Key, name = role.Name },
        scope = JsonNode.Parse(grant.ScopeJson),
        scopeKey = grant.ScopeKey,
        validUntil = grant.ValidUntil,
    };

    /// <summary>How the Anonymous principal is named where grants are listed.</summary>
    public const string AnonymousName = "Anonymous visitors";

    /// <summary>Every grant to the Anonymous principal: what anyone, signed in or not, may do.</summary>
    public Task<List<GrantInfo>> AnonymousGrantsAsync(CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            var rows = await (from g in db.RoleGrants.AsNoTracking()
                              join r in db.Roles.AsNoTracking() on g.RoleId equals r.Id
                              where g.PrincipalType == PrincipalType.Anonymous
                              orderby g.CreatedAt
                              select new { Grant = g, r.Key, r.Name }).ToListAsync(cancellationToken);
            return rows.Select(x => new GrantInfo(
                    x.Grant.Id, x.Grant.RoleId, x.Key, x.Name, x.Grant.PrincipalType, x.Grant.PrincipalId, AnonymousName,
                    JsonNode.Parse(x.Grant.ScopeJson) as JsonObject ?? [], x.Grant.ScopeKey, x.Grant.ValidUntil, x.Grant.CreatedAt))
                .ToList();
        }, cancellationToken: cancellationToken);

    /// <summary>Grants with this scope key, for example everyone with a role in one project.</summary>
    public Task<List<GrantInfo>> ListGrantsAsync(string scopeKey, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            var rows = await (from g in db.RoleGrants.AsNoTracking()
                              join r in db.Roles.AsNoTracking() on g.RoleId equals r.Id
                              where g.ScopeKey == scopeKey
                              orderby g.CreatedAt
                              select new { Grant = g, r.Key, r.Name }).ToListAsync(cancellationToken);
            List<Guid> ids = rows.Select(x => x.Grant.PrincipalId).Distinct().ToList();
            Dictionary<Guid, string> names = await db.Accounts.AsNoTracking().Where(a => ids.Contains(a.Id)).ToDictionaryAsync(a => a.Id, a => a.DisplayName, cancellationToken);
            foreach (var g in await db.Groups.AsNoTracking().Where(g => ids.Contains(g.Id)).Select(g => new { g.Id, g.Name }).ToListAsync(cancellationToken))
            {
                names[g.Id] = g.Name;
            }

            names[GuardConstants.AnonymousId] = AnonymousName;
            return rows.Select(x => new GrantInfo(
                    x.Grant.Id, x.Grant.RoleId, x.Key, x.Name, x.Grant.PrincipalType, x.Grant.PrincipalId,
                    names.GetValueOrDefault(x.Grant.PrincipalId, "(removed)"), JsonNode.Parse(x.Grant.ScopeJson) as JsonObject ?? [],
                    x.Grant.ScopeKey, x.Grant.ValidUntil, x.Grant.CreatedAt))
                .ToList();
        }, cancellationToken: cancellationToken);

    /// <summary>Keys of the roles an account holds under a scope key, directly or through any of its groups.</summary>
    public Task<HashSet<string>> RoleKeysAsync(Guid accountId, string scopeKey, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            Account? account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken);
            if (account is null || account.Status != AccountStatus.Active)
            {
                return new HashSet<string>();
            }

            List<Guid> groupIds = (await graph.GetEffectiveGroupsAsync(db, account, cancellationToken)).Select(g => g.Group.Id).ToList();
            DateTime now = DateTime.UtcNow;
            List<string> keys = await (from g in db.RoleGrants.AsNoTracking()
                                       join r in db.Roles.AsNoTracking() on g.RoleId equals r.Id
                                       where g.ScopeKey == scopeKey
                                             && (g.ValidUntil == null || g.ValidUntil > now)
                                             && ((g.PrincipalType == PrincipalType.Account && g.PrincipalId == accountId)
                                                 || (g.PrincipalType == PrincipalType.Group && groupIds.Contains(g.PrincipalId)))
                                       select r.Key).Distinct().ToListAsync(cancellationToken);
            return keys.ToHashSet(StringComparer.Ordinal);
        }, cancellationToken: cancellationToken);

    private static string Normalize(string json) => JsonNode.Parse(json)?.ToJsonString() ?? json;
}

/// <summary>Checks roles' rules against guard's subjects, for other modules (<see cref="IRoleRules"/>).</summary>
[ExposeServices(typeof(IRoleRules))]
public sealed class RoleRules : IRoleRules, ISingletonDependency
{
    public IReadOnlyList<string> Problems(JsonObject rule) => RoleCatalog.Problems(rule);
}
