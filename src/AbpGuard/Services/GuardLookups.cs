using Microsoft.EntityFrameworkCore;
using AbpGuard.Directories;
using AbpGuard.Domain;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

[ExposeServices(typeof(IAccountLookup))]
public class AccountLookup(GuardDb guardDb) : IAccountLookup, ITransientDependency
{
    public Task<AccountInfo?> GetAsync(Guid accountId, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db => (await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken)) is { } a ? ToInfo(a) : null,
            cancellationToken: cancellationToken);

    public Task<IReadOnlyDictionary<Guid, AccountInfo>> GetManyAsync(IEnumerable<Guid> accountIds, CancellationToken cancellationToken = default)
    {
        List<Guid> ids = accountIds.Distinct().ToList();
        if (ids.Count == 0)
        {
            return Task.FromResult<IReadOnlyDictionary<Guid, AccountInfo>>(new Dictionary<Guid, AccountInfo>());
        }

        return guardDb.RunAsync<IReadOnlyDictionary<Guid, AccountInfo>>(async db =>
            (await db.Accounts.AsNoTracking().Where(a => ids.Contains(a.Id)).ToListAsync(cancellationToken)).ToDictionary(a => a.Id, ToInfo),
            cancellationToken: cancellationToken);
    }

    public Task<AccountInfo?> FindByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        string normalized = GuardConstants.Normalize(username);
        return guardDb.RunAsync(async db =>
        {
            Account? account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.NormalizedUsername == normalized, cancellationToken);
            if (account?.MergedIntoId is { } survivor)
            {
                account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == survivor, cancellationToken); //
            }

            return account is null ? null : ToInfo(account);
        }, cancellationToken: cancellationToken);
    }

    public Task<IReadOnlyList<AccountInfo>> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        string normalized = GuardConstants.Normalize(email);
        return guardDb.RunAsync<IReadOnlyList<AccountInfo>>(async db => (await Addresses.ActiveWithAddress(db, normalized).AsNoTracking()
                .OrderBy(a => a.Username).Take(10).ToListAsync(cancellationToken))
            .Select(ToInfo).ToList(), cancellationToken: cancellationToken);
    }

    public Task<IReadOnlyList<AccountInfo>> SearchAsync(string text, int max = 20, CancellationToken cancellationToken = default)
    {
        string normalized = GuardConstants.Normalize(text), like = SqlLike.Containing(normalized);
        return guardDb.RunAsync<IReadOnlyList<AccountInfo>>(async db => (await db.Accounts.AsNoTracking()
                .Where(a => a.NormalizedUsername.Contains(normalized) || EF.Functions.ILike(a.DisplayName, like) || (a.OtherNames != null && EF.Functions.ILike(a.OtherNames, like)))
                .OrderBy(a => a.Username)
                .Take(max)
                .ToListAsync(cancellationToken))
            .Select(ToInfo)
            .ToList(), cancellationToken: cancellationToken);
    }

    internal static AccountInfo ToInfo(Account a) => new(a.Id, a.Username, a.DisplayName, a.MailAddress, a.Status == AccountStatus.Active, a.DirectoryId, a.Language,
        a.TimeZone, a.MergedIntoId, a.IsService) { IsAgent = a.IsAgent, DisplayNames = a.DisplayNames.Count == 0 ? null : a.DisplayNames, Picture = a.Picture };
}

[ExposeServices(typeof(IGroupLookup))]
public class GroupLookup(GuardDb guardDb) : IGroupLookup, ITransientDependency
{
    public Task<IReadOnlyDictionary<Guid, GroupInfo>> GetManyAsync(IEnumerable<Guid> groupIds, CancellationToken cancellationToken = default)
    {
        List<Guid> ids = groupIds.Distinct().ToList();
        if (ids.Count == 0)
        {
            return Task.FromResult<IReadOnlyDictionary<Guid, GroupInfo>>(new Dictionary<Guid, GroupInfo>());
        }

        return guardDb.RunAsync<IReadOnlyDictionary<Guid, GroupInfo>>(async db =>
            (await db.Groups.AsNoTracking().Where(g => ids.Contains(g.Id)).ToListAsync(cancellationToken)).ToDictionary(g => g.Id, ToInfo),
            cancellationToken: cancellationToken);
    }

    public Task<IReadOnlyList<GroupInfo>> FindAsync(string idOrName, CancellationToken cancellationToken = default)
    {
        string normalized = GuardConstants.Normalize(idOrName);
        bool byId = Guid.TryParse(idOrName, out Guid id);
        return guardDb.RunAsync<IReadOnlyList<GroupInfo>>(async db => (await db.Groups.AsNoTracking()
                .Where(g => byId ? g.Id == id : g.NormalizedName == normalized)
                .ToListAsync(cancellationToken))
            .Select(ToInfo)
            .ToList(), cancellationToken: cancellationToken);
    }

    public Task<IReadOnlyList<GroupInfo>> SearchAsync(string text, int max = 20, CancellationToken cancellationToken = default)
    {
        string normalized = GuardConstants.Normalize(text);
        return guardDb.RunAsync<IReadOnlyList<GroupInfo>>(async db => (await db.Groups.AsNoTracking()
                .Where(g => g.NormalizedName.Contains(normalized))
                .OrderBy(g => g.Name)
                .Take(max)
                .ToListAsync(cancellationToken))
            .Select(ToInfo)
            .ToList(), cancellationToken: cancellationToken);
    }

    internal static GroupInfo ToInfo(Group g) => new(g.Id, g.Name, g.Description, g.DirectoryId, g.Kind) { Names = g.Names.Count == 0 ? null : g.Names };
}

[ExposeServices(typeof(IMembershipResolver))]
public class MembershipResolver(GuardDb guardDb, MembershipGraph graph) : IMembershipResolver, ITransientDependency
{
    public async Task<bool> IsMemberAsync(Guid accountId, Guid groupId, CancellationToken cancellationToken = default) =>
        (await GetEffectiveGroupsAsync(accountId, cancellationToken)).Any(g => g.Id == groupId);

    public Task<IReadOnlyList<GroupInfo>> GetEffectiveGroupsAsync(Guid accountId, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync<IReadOnlyList<GroupInfo>>(async db =>
        {
            Account? account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken);
            if (account is null)
            {
                return [];
            }

            return (await graph.GetEffectiveGroupsAsync(db, account, cancellationToken))
                .Select(g => GroupLookup.ToInfo(g.Group))
                .ToList();
        }, cancellationToken: cancellationToken);

    public Task<IReadOnlyList<Guid>?> GetEffectiveMemberIdsAsync(string groupIdOrName, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync<IReadOnlyList<Guid>?>(async db =>
        {
            string normalized = GuardConstants.Normalize(groupIdOrName);
            List<Guid> groups = Guid.TryParse(groupIdOrName, out Guid id)
                ? await db.Groups.AsNoTracking().Where(g => g.Id == id).Select(g => g.Id).ToListAsync(cancellationToken)
                : await db.Groups.AsNoTracking().Where(g => g.NormalizedName == normalized).Select(g => g.Id).ToListAsync(cancellationToken);
            if (groups.Count == 0)
            {
                return null;
            }

            HashSet<Guid> members = [];
            foreach (Guid group in groups)
            {
                members.UnionWith((await graph.GetEffectiveMembersAsync(db, group, cancellationToken)).Select(m => m.Account.Id));
            }

            return members.ToList();
        }, cancellationToken: cancellationToken);
}
