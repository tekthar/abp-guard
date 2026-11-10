using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AbpGuard.Domain;
using AbpGuard.Services;
using AbpGuard.Acting;
using Volo.Abp;
using Volo.Abp.Domain.Entities;

namespace AbpGuard.Controllers;

/// <summary>
/// A person's own personal access tokens: listed, made (shown once, after a step-up) and revoked. A token can't
/// make another: making one is sensitive, and tokens never pass a step-up.
/// </summary>
[Route("api/guard/me/tokens")]
[GuardFeature(nameof(GuardFeatures.PersonalTokens))]
[Authorize]
public class MyTokensController(PersonalTokens tokens, GuardDb guardDb) : GuardControllerBase
{
    [HttpGet]
    public Task<List<PersonalTokenDto>> List(CancellationToken cancellationToken) => tokens.ListAsync(CurrentAccountId, activeOnly: false, cancellationToken);

    /// <summary>How long a token may live on this site, for the form that makes one.</summary>
    [HttpGet("limits")]
    public Task<TokenLimitsDto> Limits(CancellationToken cancellationToken) => guardDb.RunAsync(async db =>
        new TokenLimitsDto((await db.SecuritySettings.AsNoTracking().Where(s => s.Id == SecuritySettings.SingletonId).Select(s => (int?)s.TokenMaxDays)
            .FirstOrDefaultAsync(cancellationToken)) ?? SecuritySettings.DefaultTokenMaxDays), cancellationToken: cancellationToken);

    [HttpPost]
    [StepUp]
    public Task<NewPersonalTokenDto> Create([FromBody] CreatePersonalTokenInput input, CancellationToken cancellationToken) =>
        tokens.CreateAsync(CurrentAccountId, input, CurrentAccountId, cancellationToken);

    [HttpDelete("{id:guid}")]
    public async Task<NoContentResult> Revoke(Guid id, CancellationToken cancellationToken)
    {
        await tokens.RevokeAsync(id, CurrentAccountId, CurrentAccountId, cancellationToken);
        return NoContent();
    }
}

/// <summary>The longest a new token may live, in days.</summary>
public sealed record TokenLimitsDto(int MaxDays);

/// <summary>Every live token on the site, for site admins, who may revoke any.</summary>
[Route("api/guard/tokens")]
[GuardFeature(nameof(GuardFeatures.PersonalTokens))]
[Authorize(Policy = GuardPolicies.Admin)]
public class TokensController(PersonalTokens tokens) : GuardControllerBase
{
    [HttpGet]
    public Task<List<PersonalTokenDto>> List([FromQuery] bool all = false, CancellationToken cancellationToken = default) =>
        tokens.ListAsync(null, activeOnly: !all, cancellationToken);

    [HttpDelete("{id:guid}")]
    public async Task<NoContentResult> Revoke(Guid id, CancellationToken cancellationToken)
    {
        await tokens.RevokeAsync(id, null, CurrentAccountId, cancellationToken);
        return NoContent();
    }
}

/// <summary>A service account: an account that isn't a person, with how many live tokens it has.</summary>
public sealed record ServiceAccountDto(AccountDto Account, int Tokens);

public sealed record CreateServiceAccountInput(string Username, string? DisplayName);

/// <summary>
/// Service accounts, for site admins: accounts that aren't people, made in the internal directory with no
/// password. They take roles like anyone and act only through the tokens an admin makes for them; the AI step,
/// webhooks and agents act as them.
/// </summary>
[Route("api/guard/service-accounts")]
[Authorize(Policy = GuardPolicies.Admin)]
public class ServiceAccountsController(GuardDb guardDb, ServiceAccountMaker maker, PersonalTokens tokens) : GuardControllerBase
{
    [HttpGet]
    public Task<List<ServiceAccountDto>> List(CancellationToken cancellationToken) => guardDb.RunAsync(async db =>
    {
        DateTime now = DateTime.UtcNow;
        // Agents' accounts are made and listed by the host with their agents, and hold no tokens.
        List<Account> accounts = await db.Accounts.AsNoTracking().Where(a => a.IsService && !a.IsAgent).OrderBy(a => a.Username).ToListAsync(cancellationToken);
        List<Guid> ids = accounts.Select(a => a.Id).ToList();
        Dictionary<Guid, int> live = await db.PersonalAccessTokens.Where(t => ids.Contains(t.AccountId) && t.RevokedAt == null && t.ExpiresAt > now)
            .GroupBy(t => t.AccountId).ToDictionaryAsync(g => g.Key, g => g.Count(), cancellationToken);
        Dictionary<Guid, string> directories = await db.Directories.ToDictionaryAsync(d => d.Id, d => d.Name, cancellationToken);
        return accounts.Select(a => new ServiceAccountDto(AccountDto.From(a, directories.GetValueOrDefault(a.DirectoryId, "?")), live.GetValueOrDefault(a.Id))).ToList();
    }, cancellationToken: cancellationToken);

    [HttpPost]
    [StepUp]
    public async Task<ServiceAccountDto> Create([FromBody] CreateServiceAccountInput input, CancellationToken cancellationToken)
    {
        (Account account, string directory) = await maker.MakeAsync(new ServiceAccountInput(input.Username ?? "") { DisplayName = input.DisplayName }, cancellationToken);
        return new ServiceAccountDto(AccountDto.From(account, directory), 0);
    }

    [HttpGet("{id:guid}/tokens")]
    [GuardFeature(nameof(GuardFeatures.PersonalTokens))]
    public async Task<List<PersonalTokenDto>> Tokens(Guid id, CancellationToken cancellationToken)
    {
        await ServiceAccountAsync(id, cancellationToken);
        return await tokens.ListAsync(id, activeOnly: false, cancellationToken);
    }

    /// <summary>A token for the service account, shown once: sensitive, so it needs a step-up.</summary>
    [HttpPost("{id:guid}/tokens")]
    [GuardFeature(nameof(GuardFeatures.PersonalTokens))]
    [StepUp]
    public async Task<NewPersonalTokenDto> CreateToken(Guid id, [FromBody] CreatePersonalTokenInput input, CancellationToken cancellationToken)
    {
        await ServiceAccountAsync(id, cancellationToken);
        return await tokens.CreateAsync(id, input, CurrentAccountId, cancellationToken);
    }

    [HttpDelete("{id:guid}/tokens/{tokenId:guid}")]
    [GuardFeature(nameof(GuardFeatures.PersonalTokens))]
    public async Task<NoContentResult> RevokeToken(Guid id, Guid tokenId, CancellationToken cancellationToken)
    {
        await tokens.RevokeAsync(tokenId, id, CurrentAccountId, cancellationToken);
        return NoContent();
    }

    private Task ServiceAccountAsync(Guid id, CancellationToken cancellationToken) => guardDb.RunAsync(async db =>
    {
        if (!await db.Accounts.AnyAsync(a => a.Id == id && a.IsService && !a.IsAgent, cancellationToken))
        {
            throw new EntityNotFoundException(typeof(Account), id);
        }
    }, cancellationToken: cancellationToken);
}
