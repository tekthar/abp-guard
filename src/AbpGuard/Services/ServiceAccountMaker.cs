using Microsoft.EntityFrameworkCore;
using AbpGuard.Acting;
using AbpGuard.Controllers;
using AbpGuard.Domain;
using Volo.Abp;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>
/// Makes service accounts, for the admin page and for the host (<see cref="IServiceAccounts"/>): an internal directory
/// user with no password and no address, projected into an account marked as a service account, or an agent's.
/// </summary>
[ExposeServices(typeof(IServiceAccounts), typeof(ServiceAccountMaker))]
public class ServiceAccountMaker(GuardDb guardDb, AccountProjector projector, SecurityLog audit, IGuardEventSink events, PersonalTokens tokens, ActingContext acting)
    : IServiceAccounts, ITransientDependency
{
    public async Task<AccountInfo> CreateAsync(ServiceAccountInput input, CancellationToken cancellationToken = default) =>
        AccountLookup.ToInfo((await MakeAsync(input, cancellationToken)).Account);

    public async Task<NewServiceAccountToken> CreateTokenAsync(ServiceAccountTokenInput input, CancellationToken cancellationToken = default)
    {
        await TokenHolderAsync(input.AccountId, mustBeActive: true, cancellationToken);
        NewPersonalTokenDto made = await tokens.CreateAsync(input.AccountId,
            new CreatePersonalTokenInput(input.Name, input.Access, input.ResourceIds?.ToList(), input.Days, input.Tools?.ToList()),
            acting.SubjectId ?? input.AccountId, cancellationToken);
        return new NewServiceAccountToken(Info(made.Token), made.Secret);
    }

    public async Task<IReadOnlyList<ServiceAccountTokenInfo>> ListTokensAsync(Guid accountId, bool all = false, CancellationToken cancellationToken = default)
    {
        await TokenHolderAsync(accountId, mustBeActive: false, cancellationToken);
        return [.. (await tokens.ListAsync(accountId, activeOnly: !all, cancellationToken)).Select(Info)];
    }

    public async Task RevokeTokenAsync(Guid accountId, Guid tokenId, CancellationToken cancellationToken = default)
    {
        await TokenHolderAsync(accountId, mustBeActive: false, cancellationToken);
        await tokens.RevokeAsync(tokenId, accountId, acting.SubjectId ?? accountId, cancellationToken);
    }

    /// <summary>A service account that holds tokens: not an agent's, and active to be given one. Else not found, or refused.</summary>
    private Task TokenHolderAsync(Guid accountId, bool mustBeActive, CancellationToken cancellationToken) => guardDb.RunAsync(async db =>
    {
        Account account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId && a.IsService, cancellationToken)
            ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(Account), accountId);
        if (account.IsAgent)
        {
            throw new UserFriendlyException($"{account.Username} is an agent's account, which holds no tokens.");
        }

        if (mustBeActive && account.Status != AccountStatus.Active)
        {
            throw new UserFriendlyException($"{account.Username} isn't active, so it can't have tokens.");
        }
    }, cancellationToken: cancellationToken);

    private static ServiceAccountTokenInfo Info(PersonalTokenDto t) => new(t.Id, t.AccountId, t.Name, t.Prefix, t.Access, t.ExpiresAt, t.CreatedAt,
        t.LastUsedAt, t.RevokedAt, t.Active, t.Projects?.Select(p => p.Id).ToList(), t.Tools);

    /// <summary>
    /// Makes the account and publishes what changed, in one unit of work: the account, its audit entry and its events
    /// commit together or not at all. Returns it with its directory's name.
    /// </summary>
    internal async Task<(Account Account, string Directory)> MakeAsync(ServiceAccountInput input, CancellationToken cancellationToken)
    {
        string username = (input.Username ?? "").Trim();
        if (!Usernames.Pattern().IsMatch(username))
        {
            throw new UserFriendlyException(Usernames.Rule);
        }

        string normalized = GuardConstants.Normalize(username);
        return await guardDb.RunAsync(async db =>
        {
            if (await db.DirectoryUsers.AnyAsync(u => u.DirectoryId == GuardConstants.InternalDirectoryId && u.NormalizedUsername == normalized, cancellationToken)
                || await db.Accounts.AnyAsync(a => a.NormalizedUsername == normalized, cancellationToken))
            {
                throw new UserFriendlyException($"There's already an account called '{username}'.");
            }

            // No password and no address: it can't sign in, and no reset or mail reaches it.
            db.DirectoryUsers.Add(new DirectoryUser(Guid.NewGuid(), GuardConstants.InternalDirectoryId, $"internal:{normalized}", username)
            {
                DisplayName = string.IsNullOrWhiteSpace(input.DisplayName) ? username : DisplayNames.Check(input.DisplayName.Trim()),
            });
            await db.SaveChangesAsync(cancellationToken);
            List<object> raised = await projector.RebuildAsync(db, [normalized], cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            Account account = await db.Accounts.FirstAsync(a => a.NormalizedUsername == normalized, cancellationToken);
            account.MakeService(input.Agent);
            string directory = await db.Directories.Where(d => d.Id == account.DirectoryId).Select(d => d.Name).FirstAsync(cancellationToken);
            audit.Add(db, SecurityAuditTypes.AccountCreated, new AuditTarget("Account", account.Id, account.Username),
                input.Agent ? new { directory, service = true, agent = true } : new { directory, service = true });
            await db.SaveChangesAsync(cancellationToken);
            // In the account's unit of work: the events commit with it, so a failure leaves no account behind.
            foreach (object e in raised)
            {
                await GuardEvents.PublishAsync(events, e, cancellationToken);
            }

            return (account, directory);
        }, requiresNew: true, cancellationToken, isTransactional: true);
    }
}
