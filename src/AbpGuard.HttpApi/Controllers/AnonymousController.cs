using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AbpGuard.Domain;
using AbpGuard.Services;
using AbpGuard.Acting;
using Volo.Abp.Domain.Entities;

namespace AbpGuard.Controllers;

/// <summary>One grant to Anonymous visitors: the role, where (a project), and the page that manages it.</summary>
public sealed record AnonymousGrantDto(Guid Id, string RoleKey, string RoleName, string? ScopeKey, string? Scope, string? Href, DateTime? ValidUntil, DateTime CreatedAt);

/// <summary>
/// Anonymous visitors, for site admins: every grant to the Anonymous principal in one list, because what
/// it's given, anyone on the internet gets. Grants are made in a project's members; any can be revoked here.
/// </summary>
[Route("api/guard/anonymous")]
[Authorize(Policy = GuardPolicies.Admin)]
public class AnonymousController(RoleCatalog roles, IEnumerable<IGrantScopeDescriber> describers) : GuardControllerBase
{
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
                g.ValidUntil, g.CreatedAt))
            .ToList();
    }

    [HttpDelete("{grantId:guid}")]
    [StepUp]
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
