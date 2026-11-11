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

    public async Task<AccountInfo> RenameAsync(Guid accountId, string displayName, IReadOnlyDictionary<string, string>? displayNames,
        CancellationToken cancellationToken = default)
    {
        string name = AccountCorrections.CheckNames(displayName, displayNames);
        Account account = await guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken)
                ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(Account), accountId);
            if (!account.IsService || account.MergedIntoId is not null)
            {
                throw new UserFriendlyException("Only a service account is renamed here: people correct their own names.");
            }

            // Compared before anything is set, so a rename to the same names writes nothing and tells no one.
            Dictionary<string, string> wanted = displayNames is null ? account.DisplayNames
                : displayNames.Where(n => !string.IsNullOrWhiteSpace(n.Key) && !string.IsNullOrWhiteSpace(n.Value))
                    .ToDictionary(n => n.Key.Trim(), n => n.Value.Trim(), StringComparer.Ordinal);
            bool othersChanged = wanted.Count != account.DisplayNames.Count || wanted.Any(n => account.DisplayNames.GetValueOrDefault(n.Key) != n.Value);
            string before = account.DisplayName;
            if (before == name && !othersChanged)
            {
                return account;
            }

            if (othersChanged)
            {
                account.SetDisplayNames(wanted);
            }

            account.DisplayName = name;
            // Its internal directory's record keeps the name too, so rebuilding the account from it keeps the new one.
            if (account.DirectoryUserId is { } recordId && await db.DirectoryUsers.FirstOrDefaultAsync(u => u.Id == recordId, cancellationToken) is { } record)
            {
                record.DisplayName = name;
                record.DisplayNames = new Dictionary<string, string>(account.DisplayNames);
            }

            audit.Add(db, SecurityAuditTypes.AccountRenamed, new AuditTarget("Account", account.Id, account.Username),
                new { before, after = name, names = account.DisplayNames });
            await db.SaveChangesAsync(cancellationToken);
            // In the rename's unit of work, as an account's making is: the name, its audit entry and the event commit together.
            await GuardEvents.PublishAsync(events, new AccountChangedEto(account.Id, account.Username, before, name, null, null), cancellationToken);
            return account;
        }, requiresNew: true, cancellationToken, isTransactional: true);
        return AccountLookup.ToInfo(account);
    }

    public async Task<AccountInfo> SetPictureAsync(Guid accountId, string? picture, CancellationToken cancellationToken = default)
    {
        if (picture is not null && !AccountPictures.IsPath(picture))
        {
            throw new UserFriendlyException("A picture is a path on this site: \"/\", then letters, digits, \"/\", \".\", \"_\" and \"-\", at most 300 characters.");
        }

        Account account = await guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken)
                ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(Account), accountId);
            if (!account.IsService || account.MergedIntoId is not null)
            {
                throw new UserFriendlyException("Only a service account's picture is set here: people's come later.");
            }

            string? before = account.Picture;
            if (before == picture)
            {
                return account;
            }

            account.Picture = picture;
            audit.Add(db, SecurityAuditTypes.AccountPictureChanged, new AuditTarget("Account", account.Id, account.Username), new { before, after = picture });
            await db.SaveChangesAsync(cancellationToken);
            // In the change's unit of work, as a rename is: the picture, its audit entry and the event commit together. No
            // name or address changed, so copies of them have nothing to do.
            await GuardEvents.PublishAsync(events, new AccountChangedEto(account.Id, account.Username, null, null, null, null), cancellationToken);
            return account;
        }, requiresNew: true, cancellationToken, isTransactional: true);
        return AccountLookup.ToInfo(account);
    }

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

        Usernames.EnsureNotReserved(username, input.DisplayName);
        if (input.DisplayNames is { Count: > 0 })
        {
            // Names in other languages, as a person's: the name as written (English) is required beside them.
            if (string.IsNullOrWhiteSpace(input.DisplayName))
            {
                throw new UserFriendlyException("Give the name as written (in English) as well as the other languages'.");
            }

            AccountCorrections.CheckNames(input.DisplayName, input.DisplayNames);
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
            if (input.DisplayNames is { Count: > 0 } names)
            {
                account.SetDisplayNames(names);
            }
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
