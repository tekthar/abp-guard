using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AbpGuard.Domain;
using AbpGuard.Services;
using AbpGuard.Acting;
using Microsoft.EntityFrameworkCore;
using Volo.Abp.Domain.Entities;

namespace AbpGuard.Controllers;

/// <summary>One grant to Anonymous visitors: the role, where (a project), and the page that manages it.</summary>
public sealed record AnonymousGrantDto(Guid Id, string RoleKey, string RoleName, string? ScopeKey, string? Scope, string? Href, DateTime? ValidUntil, DateTime CreatedAt)
{
    /// <summary>The place's short code (a project's key, a portal's path), when the host gives one (0.9.0).</summary>
    public string? Code { get; init; }

    /// <summary>The role's id, for changing it (0.9.0).</summary>
    public Guid RoleId { get; init; }
}

/// <summary>A place where anonymous visitors may be given a role, and the roles that suit it (0.9.0).</summary>
public sealed record AnonymousPlaceDto(string ScopeKey, string Label, string? Code, string? Href, List<AnonymousRoleDto> Roles);

/// <summary>A role anonymous visitors may have in a place: what it's called and what it lets them do, by language.</summary>
public sealed record AnonymousRoleDto(Guid Id, string Key, string Name, string? Description, Dictionary<string, string> Names, Dictionary<string, string> Descriptions);

public sealed record GiveAnonymousRoleInput(Guid RoleId, string ScopeKey);

public sealed record ChangeAnonymousRoleInput(Guid RoleId);

/// <summary>
/// Anonymous visitors, for site admins: every grant to the Anonymous principal in one list, because what
/// it's given, anyone on the internet gets. Grants are made in a project's members, or here in a place the host lists
/// (0.9.0, with a role that keeps to it); any can be revoked here.
/// </summary>
[Route("api/guard/anonymous")]
[Authorize(Policy = GuardPolicies.Admin)]
public class AnonymousController(RoleCatalog roles, IEnumerable<IGrantScopeDescriber> describers, AnonymousGrants anonymous, GuardDb guardDb) : GuardControllerBase
{
    /// <summary>The host's places where anonymous visitors may have a role, each with the roles that suit it; none without a catalog.</summary>
    [HttpGet("places")]
    public async Task<List<AnonymousPlaceDto>> Places(CancellationToken cancellationToken)
    {
        List<GrantScopeOption> places = await anonymous.PlacesAsync(cancellationToken);
        List<Guid> ids = places.SelectMany(p => p.RoleIds).Distinct().ToList();
        Dictionary<Guid, Role> found = await guardDb.RunAsync(db => db.Roles.AsNoTracking().Where(r => ids.Contains(r.Id)).ToDictionaryAsync(r => r.Id, cancellationToken),
            cancellationToken: cancellationToken);
        return places.Select(p => new AnonymousPlaceDto(p.ScopeKey, p.Label, p.Code, p.Href, p.RoleIds.Where(found.ContainsKey).Select(id => found[id])
                .Select(r => new AnonymousRoleDto(r.Id, r.Key, r.Name, r.Description, r.Names, r.Descriptions)).ToList()))
            .ToList();
    }

    /// <summary>Gives anonymous visitors a role in a place the host lists, when the role keeps to it. Anyone on the internet gets it.</summary>
    [HttpPost]
    [StepUp(StepUpCategories.Roles)]
    public async Task<AnonymousGrantDto> Give([FromBody] GiveAnonymousRoleInput input, CancellationToken cancellationToken)
    {
        Guid id = await anonymous.GiveAsync(input.RoleId, input.ScopeKey, CurrentAccountId, cancellationToken);
        return (await List(cancellationToken)).First(g => g.Id == id);
    }

    /// <summary>Changes the role a grant gives anonymous visitors, in one step and with the same checks.</summary>
    [HttpPut("{grantId:guid}")]
    [StepUp(StepUpCategories.Roles)]
    public async Task<AnonymousGrantDto> Change(Guid grantId, [FromBody] ChangeAnonymousRoleInput input, CancellationToken cancellationToken)
    {
        Guid id = await anonymous.ChangeAsync(grantId, input.RoleId, CurrentAccountId, cancellationToken);
        return (await List(cancellationToken)).First(g => g.Id == id);
    }

    [HttpGet]
    public async Task<List<AnonymousGrantDto>> List(CancellationToken cancellationToken)
    {
        List<GrantInfo> grants = await roles.AnonymousGrantsAsync(cancellationToken);
        List<string> keys = grants.Select(g => g.ScopeKey).OfType<string>().Distinct().ToList();
        Dictionary<string, GrantScopeLabel> labels = [];
        foreach (IGrantScopeDescriber describer in describers)
        {
            foreach ((string key, GrantScopeLabel label) in await describer.DescribeAsync(keys, cancellationToken))
            {
                labels[key] = label;
            }
        }

        return grants.Select(g => new AnonymousGrantDto(g.Id, g.RoleKey, g.RoleName, g.ScopeKey,
                g.ScopeKey is { } k && labels.TryGetValue(k, out GrantScopeLabel? l) ? l.Label : g.ScopeKey, g.ScopeKey is { } h ? labels.GetValueOrDefault(h)?.Href : null,
                g.ValidUntil, g.CreatedAt)
            {
                Code = g.ScopeKey is { } c ? labels.GetValueOrDefault(c)?.Code : null,
                RoleId = g.RoleId,
            })
            .ToList();
    }

    [HttpDelete("{grantId:guid}")]
    [StepUp(StepUpCategories.Roles)]
    public async Task<NoContentResult> Revoke(Guid grantId, CancellationToken cancellationToken)
    {
        if ((await roles.AnonymousGrantsAsync(cancellationToken)).All(g => g.Id != grantId))
        {
            throw new EntityNotFoundException(typeof(RoleGrant), grantId);
        }

        await roles.RevokeAsync(grantId, cancellationToken: cancellationToken);
        return NoContent();
    }
}
