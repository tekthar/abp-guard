using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Casl;
using AbpGuard.Domain;
using AbpGuard.Acting;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>
/// Subjects guard exposes to rules, and the member paths rules may filter on: guard's own, added to the registry every
/// module shares (<see cref="AbilitySubjects"/>) before guard first reads it.
/// </summary>
public static class GuardSubjects
{
    static GuardSubjects() => AbilitySubjects.Registry
        .Add<Account>("Account", s => s
            .ConditionFields("id", "directoryId", "status", "username", "lockedLocally")
            .Fields("displayName", "email", "status"))
        .Add<Group>("Group", s => s.ConditionFields("id", "directoryId", "isLocal").Fields("name", "description"))
        .Add<UserDirectory>("Directory", s => s.ConditionFields("id", "type", "isActive"))
        .Add<RoleSubject>("Role"); // a host adds its own (a "Plugin" subject, say)

    public static SubjectRegistry Registry => AbilitySubjects.Registry;

    /// <summary>Any matching deny wins (<see cref="AbilitySubjects.Options"/>).</summary>
    public static AbilityOptions Options => AbilitySubjects.Options;

    /// <summary>Marker types for subjects that only get type-level checks for now.</summary>
    public sealed class RoleSubject;
}

/// <summary>
/// Builds an account's <see cref="Ability"/> from the roles granted to it directly or to any of its effective
/// groups (nested groups count). Each grant's scope fills that grant's ${grant.*} placeholders.
/// Kept between requests while the permission stamp stays the same, and within a request once read.
/// The one way to an ability: when the account is the request's subject, the request's limits apply.
/// </summary>
[ExposeServices(typeof(AbilityFactory), typeof(IAbilities))]
public class AbilityFactory(GuardDb guardDb, MembershipGraph graph, ILogger<AbilityFactory> logger, IEnumerable<IGrantScopeExpander> expanders, AbilityCache kept,
    ActingContext acting, IEnumerable<IAbilityLimit> limits, IEnumerable<IAbilityDenies> denies)
    : IScopedDependency, IAbilities
{
    private readonly Dictionary<Guid, Ability> _cache = [];

    public static Ability None { get; } = new AbilityBuilder(GuardSubjects.Registry, GuardSubjects.Options).Build();

    /// <summary>
    /// The account's ability: its own for anyone else (a notice's recipient, a mail's sender), and for the request's
    /// subject, its own with the request's limits.
    /// </summary>
    public async Task<Ability> ForAccountAsync(Guid accountId, CancellationToken cancellationToken = default)
    {
        if (_cache.TryGetValue(accountId, out Ability? cached))
        {
            return cached;
        }

        Ability own = await OwnAsync(accountId, cancellationToken);
        return _cache[accountId] = Limit(own, accountId, acting, limits);
    }

    /// <summary>
    /// Whether a role granted to the account, itself or through its groups, can do everything: an administrator's
    /// rights, whatever the account's status (a locked admin's too). A rule on <c>all</c> has no conditions or fields.
    /// </summary>
    public Task<bool> HoldsAdminRightsAsync(Guid accountId, CancellationToken cancellationToken = default) => guardDb.RunAsync(async db =>
    {
        Account? account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken);
        if (account is null)
        {
            return false;
        }

        // Its groups as they'd be were it active: a locked account is in none until it's unlocked. The copy isn't tracked.
        account.Status = AccountStatus.Active;
        List<Guid> groupIds = (await graph.GetEffectiveGroupsAsync(db, account, cancellationToken)).Select(g => g.Group.Id).ToList();
        DateTime now = DateTime.UtcNow;
        List<string> rules = await db.RoleGrants.AsNoTracking()
            .Where(g => (g.PrincipalType == PrincipalType.Account && g.PrincipalId == accountId) || (g.PrincipalType == PrincipalType.Group && groupIds.Contains(g.PrincipalId)))
            .Where(g => g.ValidUntil == null || g.ValidUntil > now)
            .Join(db.RoleRules, g => g.RoleId, r => r.RoleId, (g, r) => r.Json)
            .ToListAsync(cancellationToken);
        return rules.Any(ManagesAll);
    }, cancellationToken: cancellationToken);

    private static bool ManagesAll(string json)
    {
        JsonNode? rule = JsonNode.Parse(json);
        static bool Has(JsonNode? node, string value) => node switch
        {
            JsonArray array => array.Any(n => n?.GetValue<string>() == value),
            JsonValue one => one.GetValue<string>() == value,
            _ => false,
        };

        return rule?["inverted"]?.GetValue<bool>() != true && Has(rule?["action"], "manage") && Has(rule?["subject"], "all");
    }

    /// <summary>The request's limits, on the request's subject only.</summary>
    public static Ability Limit(Ability own, Guid accountId, ActingContext acting, IEnumerable<IAbilityLimit> limits) =>
        acting.SubjectId == accountId ? limits.Aggregate(own, (ability, limit) => limit.Apply(ability, acting)) : own;

    private async Task<Ability> OwnAsync(Guid accountId, CancellationToken cancellationToken)
    {
        // The stamp is read before anything the ability is built from, so an ability is never kept under a stamp newer
        // than its data.
        long stamp = await StampAsync(cancellationToken);
        if (kept.TryGet(accountId, stamp, out Ability keptAbility))
        {
            return keptAbility;
        }

        (Ability ability, DateTime? until, List<Guid>? groups) = await guardDb.RunAsync(async db =>
        {
            Account? account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken);
            if (account is null || account.Status != AccountStatus.Active)
            {
                return (None, (DateTime?)null, (List<Guid>?)null);
            }

            List<Guid> groupIds = (await graph.GetEffectiveGroupsAsync(db, account, cancellationToken)).Select(g => g.Group.Id).ToList();
            DateTime now = DateTime.UtcNow;
            List<RoleGrant> grants = await db.RoleGrants.AsNoTracking()
                .Where(g => (g.PrincipalType == PrincipalType.Account && g.PrincipalId == account.Id)
                         || (g.PrincipalType == PrincipalType.Group && groupIds.Contains(g.PrincipalId))
                         || g.PrincipalType == PrincipalType.Anonymous) // what anyone may do, a signed-in person may too
                .Where(g => g.ValidUntil == null || g.ValidUntil > now)
                .ToListAsync(cancellationToken);
            object user = new { user = new { id = account.Id, username = account.Username, directoryId = account.DirectoryId, groupIds } };
            // What Anonymous visitors are granted, everyone gets; but its denies (a customer role's hidden fields) are for
            // people it's all they have there, not for the team that also has a role of its own in that scope.
            HashSet<string?> ownScopes = grants.Where(g => g.PrincipalType != PrincipalType.Anonymous).Select(g => g.ScopeKey).ToHashSet();
            bool siteWide = ownScopes.Contains(null); // a site role (an administrator's) is theirs everywhere
            HashSet<Guid> allowOnly = grants.Where(g => g.PrincipalType == PrincipalType.Anonymous && (siteWide || ownScopes.Contains(g.ScopeKey))).Select(g => g.Id).ToHashSet();
            return (await BuildAsync(db, grants, user, account.Id, cancellationToken, allowOnly), Until(grants), groupIds);
        }, cancellationToken: cancellationToken);

        if (groups is not null)
        {
            ability = await WithDeniesAsync(ability, accountId, groups, cancellationToken);
        }

        kept.Set(accountId, stamp, ability, until);
        return ability;
    }

    /// <summary>
    /// What someone who isn't signed in may do: only what's granted to the Anonymous principal. Rules that
    /// name the person (${user.id}) match no one.
    /// </summary>
    public async Task<Ability> ForAnonymousAsync(CancellationToken cancellationToken = default)
    {
        if (_cache.TryGetValue(GuardConstants.AnonymousId, out Ability? cached))
        {
            return cached;
        }

        long stamp = await StampAsync(cancellationToken);
        if (kept.TryGet(GuardConstants.AnonymousId, stamp, out Ability keptAbility))
        {
            return _cache[GuardConstants.AnonymousId] = keptAbility;
        }

        (Ability ability, DateTime? until) = await guardDb.RunAsync(async db =>
        {
            DateTime now = DateTime.UtcNow;
            List<RoleGrant> grants = await db.RoleGrants.AsNoTracking()
                .Where(g => g.PrincipalType == PrincipalType.Anonymous && (g.ValidUntil == null || g.ValidUntil > now))
                .ToListAsync(cancellationToken);
            object user = new { user = new { id = GuardConstants.AnonymousId, username = "", directoryId = Guid.Empty, groupIds = new List<Guid>() } };
            return (grants.Count == 0 ? None : await BuildAsync(db, grants, user, GuardConstants.AnonymousId, cancellationToken), Until(grants));
        }, cancellationToken: cancellationToken);

        if (!ReferenceEquals(ability, None))
        {
            ability = await WithDeniesAsync(ability, null, [], cancellationToken);
        }

        kept.Set(GuardConstants.AnonymousId, stamp, ability, until);
        _cache[GuardConstants.AnonymousId] = ability;
        return ability;
    }

    /// <summary>
    /// The permission stamp, read for each person a request needs (not once for the request: one that changes
    /// someone's grants and then asks for their ability sees the stamp its change moved on).
    /// </summary>
    private Task<long> StampAsync(CancellationToken cancellationToken) =>
        guardDb.RunAsync(db => db.PermissionStamps.AsNoTracking().Where(s => s.Id == PermissionStamp.RowId).Select(s => s.Version).FirstOrDefaultAsync(cancellationToken),
            cancellationToken: cancellationToken);

    /// <summary>The ability with every module's denies for this person (M9 step 6d), which any matching deny wins over.</summary>
    private async Task<Ability> WithDeniesAsync(Ability ability, Guid? accountId, IReadOnlyCollection<Guid> groupIds, CancellationToken cancellationToken)
    {
        List<RawRule> added = [];
        foreach (IAbilityDenies module in denies)
        {
            added.AddRange(await module.DeniesAsync(accountId, groupIds, cancellationToken));
        }

        return added.Count == 0 ? ability : AbilityRules.Rebuild(ability, rule => [rule], added);
    }

    /// <summary>When an ability built from these grants stops being right on its own: the first "valid until" among them.</summary>
    private static DateTime? Until(List<RoleGrant> grants) => grants.Where(g => g.ValidUntil != null).Min(g => g.ValidUntil);

    /// <summary>The ability the grants give, each grant in its own scope and in any scope a module widens it to.</summary>
    private async Task<Ability> BuildAsync(Data.GuardDbContext db, List<RoleGrant> grants, object user, Guid subject, CancellationToken cancellationToken,
        HashSet<Guid>? allowOnly = null)
    {
        List<Guid> roleIds = grants.Select(g => g.RoleId).Distinct().ToList();
        ILookup<Guid, string> ruleJson = (await db.RoleRules.AsNoTracking().Where(r => roleIds.Contains(r.RoleId)).OrderBy(r => r.Order).ToListAsync(cancellationToken))
            .ToLookup(r => r.RoleId, r => r.Json);
        ILookup<Guid, RawRule> rules = ruleJson.SelectMany(g => g.Select(j => (g.Key, Rule: RawRule.Parse(j)))).ToLookup(x => x.Key, x => x.Rule);

        // Rules for a widened scope, made once per role, read-only or not, and list-valued placeholders.
        Dictionary<(Guid Role, bool ReadOnly, string Lists), List<RawRule>> widened = [];
        List<RawRule> Widened(Guid role, bool readOnly, JsonObject scope)
        {
            HashSet<string> lists = scope.Where(p => p.Value is JsonArray).Select(p => p.Key).ToHashSet(StringComparer.Ordinal);
            (Guid, bool, string) key = (role, readOnly, string.Join(",", lists.Order(StringComparer.Ordinal)));
            if (!widened.TryGetValue(key, out List<RawRule>? found))
            {
                found = ruleJson[role].Select(j => readOnly ? ReadOnly(j) : j).OfType<string>().Select(j => RawRule.Parse(ListValued(j, lists))).ToList();
                widened[key] = found;
            }

            return found;
        }

        AbilityBuilder builder = new AbilityBuilder(GuardSubjects.Registry, GuardSubjects.Options).WithVariables(user);
        // Each grant applies in its own scope, and in any scope a module widens it to.
        List<(RoleGrant Grant, JsonObject Scope, bool ReadOnly)> applied = [];
        Dictionary<Guid, JsonObject> ownScopes = [];
        foreach (RoleGrant grant in grants)
        {
            JsonObject own = JsonNode.Parse(grant.ScopeJson) as JsonObject ?? [];
            ownScopes[grant.Id] = own;
            applied.Add((grant, own, false));
            foreach (IGrantScopeExpander expander in expanders)
            {
                foreach (GrantExpansion expansion in await expander.ExpandAsync(own, cancellationToken))
                {
                    applied.Add((grant, expansion.Scope, expansion.ReadOnly));
                }
            }
        }

        foreach ((RoleGrant grant, JsonObject grantScope, bool readOnly) in applied)
        {
            object scope = new { grant = grantScope };
            List<RawRule> grantRules = ReferenceEquals(grantScope, ownScopes[grant.Id]) ? rules[grant.RoleId].ToList() : Widened(grant.RoleId, readOnly, grantScope);
            if (allowOnly?.Contains(grant.Id) == true)
            {
                grantRules = grantRules.Where(r => !r.Inverted).ToList();
            }
            if (grantRules.Count == 0)
            {
                continue;
            }

            try
            {
                // Check each grant on its own so one broken grant can't take down the others.
                _ = new AbilityBuilder(GuardSubjects.Registry, GuardSubjects.Options).WithVariables(user).AddRange(grantRules, scope).Build();
            }
            catch (CaslConfigurationException ex)
            {
                if (grantRules.Any(r => r.Inverted))
                {
                    // Skipping a grant with deny rules could widen access: deny everything instead.
                    logger.LogError("Grant {Grant} has an invalid deny rule ({Error}); account {Account} gets no access until it is fixed.", grant.Id, ex.Message, subject);
                    return None;
                }

                logger.LogWarning("Grant {Grant} skipped: {Error}", grant.Id, ex.Message);
                continue;
            }

            builder.AddRange(grantRules, scope);
        }

        return RuleMerging.Merged(builder.Build());
    }

    /// <summary>
    /// A rule narrowed to reading: its actions become "read" when it allows (or denies) reading or managing; any other
    /// rule is dropped. Used where a grant reaches further than where it was given, for reading only.
    /// </summary>
    /// <summary>
    /// A rule for a scope whose values may be lists: a condition that is exactly "${grant.X}" becomes
    /// { "$in": "${grant.X} } when X holds a list, so one rule covers every project a grant reaches instead of one rule
    /// per project.
    /// </summary>
    internal static string ListValued(string json, IReadOnlySet<string> lists)
    {
        if (lists.Count == 0 || JsonNode.Parse(json) is not JsonObject rule || rule["conditions"] is not JsonObject conditions)
        {
            return json;
        }

        void Walk(JsonObject node)
        {
            foreach ((string name, JsonNode? value) in node.ToList())
            {
                switch (value)
                {
                    case JsonValue v when v.TryGetValue(out string? text) && text.StartsWith("${grant.", StringComparison.Ordinal) && text.EndsWith('}')
                                          && lists.Contains(text[8..^1]):
                        node[name] = new JsonObject { ["$in"] = text };
                        break;
                    case JsonObject child:
                        Walk(child);
                        break;
                    case JsonArray items:
                        foreach (JsonObject item in items.OfType<JsonObject>())
                        {
                            Walk(item);
                        }

                        break;
                }
            }
        }

        Walk(conditions);
        return rule.ToJsonString();
    }

    internal static string? ReadOnly(string json)
    {
        if (JsonNode.Parse(json) is not JsonObject rule)
        {
            return null;
        }

        IEnumerable<string> actions = rule["action"] switch
        {
            JsonArray list => list.Select(a => a?.GetValue<string>() ?? ""),
            JsonValue one => [one.GetValue<string>()],
            _ => [],
        };
        if (!actions.Any(a => a is "read" or "manage"))
        {
            return null;
        }

        rule["action"] = "read";
        return rule.ToJsonString();
    }
}
