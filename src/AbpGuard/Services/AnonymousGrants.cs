using System.Text.Json.Nodes;
using AbpGuard.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Volo.Abp;
using Volo.Abp.DependencyInjection;
using Volo.Abp.Domain.Entities;

namespace AbpGuard.Services;

/// <summary>
/// Giving anonymous visitors a role in one of the host's places (0.9.0), with the guard rails a grant to everyone on the
/// internet needs. The host lists its places and the roles that suit each (<see cref="IGrantScopeCatalog"/>, purpose
/// <see cref="GrantPurposes.Anonymous"/>); a role is given only when every allow rule of it conforms
/// (<see cref="Problem"/>): limited to the place at the top of its conditions, opening only the place's subjects, never
/// Guard's own (people, groups, directories, roles) and never <c>manage</c>. Deny rules only narrow, so they stay.
/// </summary>
public class AnonymousGrants(GuardDb guardDb, RoleCatalog roles, IEnumerable<IGrantScopeCatalog> catalogs) : ITransientDependency
{
    /// <summary>Guard's own subjects, and every subject: never opened to anonymous visitors, whatever the place.</summary>
    public static readonly IReadOnlySet<string> ClosedSubjects =
        new HashSet<string>(["all", "Account", "Group", "Directory", "Role", "Grant", "Token", "SecurityEvent", "Settings"], StringComparer.OrdinalIgnoreCase);

    /// <summary>The host's places for anonymous visitors, from every catalog, by scope key.</summary>
    public async Task<List<GrantScopeOption>> PlacesAsync(CancellationToken ct)
    {
        Dictionary<string, GrantScopeOption> places = new(StringComparer.Ordinal);
        foreach (IGrantScopeCatalog catalog in catalogs)
        {
            foreach (GrantScopeOption option in await catalog.ListAsync(GrantPurposes.Anonymous, ct))
            {
                places.TryAdd(option.ScopeKey, option);
            }
        }

        return [.. places.Values];
    }

    /// <summary>Gives anonymous visitors the role in the place: refused unless the place lists the role and every allow rule conforms.</summary>
    public async Task<Guid> GiveAsync(Guid roleId, string scopeKey, Guid? actor, CancellationToken ct)
    {
        GrantScopeOption place = await CheckAsync(roleId, scopeKey, ct);
        return await roles.GrantAsync(roleId, PrincipalType.Anonymous, GuardConstants.AnonymousId, place.Scope, place.ScopeKey, null, actor, ct);
    }

    /// <summary>Changes the role of a grant to anonymous visitors, in one step and with the same checks.</summary>
    public async Task<Guid> ChangeAsync(Guid grantId, Guid roleId, Guid? actor, CancellationToken ct)
    {
        RoleGrant grant = await guardDb.RunAsync(db => db.RoleGrants.AsNoTracking()
                .FirstOrDefaultAsync(g => g.Id == grantId && g.PrincipalType == PrincipalType.Anonymous, ct), cancellationToken: ct)
            ?? throw new EntityNotFoundException(typeof(RoleGrant), grantId);
        if (grant.RoleId == roleId)
        {
            return grant.Id;
        }

        GrantScopeOption place = await CheckAsync(roleId, grant.ScopeKey ?? "", ct);
        return await guardDb.RunAsync(async _ =>
        {
            await roles.RevokeAsync(grantId, cancellationToken: ct);
            return await roles.GrantAsync(roleId, PrincipalType.Anonymous, GuardConstants.AnonymousId, place.Scope, place.ScopeKey, grant.ValidUntil, actor, ct);
        }, requiresNew: true, ct, isTransactional: true);
    }

    private async Task<GrantScopeOption> CheckAsync(Guid roleId, string scopeKey, CancellationToken ct)
    {
        GrantScopeOption place = (await PlacesAsync(ct)).FirstOrDefault(p => p.ScopeKey == scopeKey)
            ?? throw new UserFriendlyException("Anonymous visitors can't be given a role there.");
        if (!place.RoleIds.Contains(roleId))
        {
            throw new UserFriendlyException($"That role isn't one anonymous visitors may have in {place.Label}.");
        }

        List<string> rules = await guardDb.RunAsync(db => db.RoleRules.AsNoTracking().Where(r => r.RoleId == roleId).OrderBy(r => r.Order).Select(r => r.Json)
            .ToListAsync(ct), cancellationToken: ct);
        if (rules.Select(r => Problem(r, place.Scope, place.Subjects)).FirstOrDefault(p => p is not null) is { } problem)
        {
            throw new UserFriendlyException($"Anonymous visitors can't have this role: one of its rules {problem}.", GuardErrorCodes.RoleGivenToAnonymous);
        }

        return place;
    }

    /// <summary>
    /// Why an allow rule mustn't reach anonymous visitors in a place with this scope, or null when it may (a deny rule
    /// always may: it only narrows). It must be limited to the place at the top of its conditions (an AND: a
    /// <c>${grant.*}</c> of the scope's, directly or under a top-level <c>$and</c>, never only under <c>$or</c>, <c>$nor</c>
    /// or <c>$not</c>, where it could be escaped), open only the place's subjects when it names some, never Guard's own or
    /// <c>all</c>, and never <c>manage</c>.
    /// </summary>
    public static string? Problem(string ruleJson, JsonObject scope, IReadOnlyCollection<string>? subjects)
    {
        if (JsonNode.Parse(ruleJson) is not JsonObject rule)
        {
            return "can't be read";
        }

        if (rule["inverted"] is JsonValue inverted && inverted.TryGetValue(out bool deny) && deny)
        {
            return null;
        }

        if (Names(rule["action"]).Any(a => string.Equals(a, "manage", StringComparison.OrdinalIgnoreCase)))
        {
            return "manages what it covers";
        }

        foreach (string subject in Names(rule["subject"]))
        {
            if (ClosedSubjects.Contains(subject))
            {
                return subject == "all" ? "covers everything" : $"opens {subject}, which is {(subject is "Account" ? "people" : "the site's own")}";
            }

            if (subjects is { Count: > 0 } && !subjects.Contains(subject, StringComparer.OrdinalIgnoreCase))
            {
                return $"opens {subject}, which this place doesn't";
            }
        }

        HashSet<string> placeholders = scope.Select(p => "${grant." + p.Key + "}").ToHashSet(StringComparer.Ordinal);
        return rule["conditions"] is JsonObject conditions && LimitedAtTop(conditions, placeholders) ? null : "isn't limited to the place";
    }

    /// <summary>
    /// Whether an anonymous grant's role may apply as it stands (an ability's last line of defence, for a role whose rules
    /// a host changed after it was given): every allow rule conforms, the place's subjects aside. When not, the grant's
    /// allow rules are left out and it's logged.
    /// </summary>
    public static bool Conforms(IEnumerable<string> ruleJson, JsonObject scope, ILogger logger, Guid grantId)
    {
        foreach (string rule in ruleJson)
        {
            if (Problem(rule, scope, null) is { } problem)
            {
                logger.LogError("Grant {Grant} gives anonymous visitors a role one of whose rules {Problem}: its allow rules are left out until the role or the grant is fixed.",
                    grantId, problem);
                return false;
            }
        }

        return true;
    }

    private static bool LimitedAtTop(JsonObject conditions, HashSet<string> placeholders)
    {
        foreach ((string key, JsonNode? value) in conditions)
        {
            if (key == "$and" && value is JsonArray all && all.OfType<JsonObject>().Any(part => LimitedAtTop(part, placeholders)))
            {
                return true;
            }

            if (key.StartsWith('$'))
            {
                continue; // $or, $nor, $not and the rest: a limit inside them can be escaped
            }

            if (IsPlaceholder(value, placeholders)
                || (value is JsonObject op && (IsPlaceholder(op["$eq"], placeholders) || IsPlaceholder(op["$in"], placeholders))))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsPlaceholder(JsonNode? node, HashSet<string> placeholders) =>
        node is JsonValue v && v.TryGetValue(out string? text) && text is not null && placeholders.Contains(text);

    private static IEnumerable<string> Names(JsonNode? node) => node switch
    {
        JsonArray list => list.OfType<JsonValue>().Select(v => v.TryGetValue(out string? s) ? s : null).OfType<string>(),
        JsonValue one when one.TryGetValue(out string? s) && s is not null => [s],
        _ => [],
    };
}
