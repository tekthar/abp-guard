using Microsoft.EntityFrameworkCore;
using AbpGuard.Controllers;
using AbpGuard.Data;
using AbpGuard.Domain;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>
/// Organizations from an import (M6 step 12): the one the import made before (by id), else the internal
/// directory's organization with that name, else a new one. The source's members are added by hand, as an admin would
/// add them, so later syncs and domain rules leave them be; members it has already stay.
/// </summary>
[ExposeServices(typeof(OrganizationImport), typeof(IOrganizationImport))]
public class OrganizationImport(GuardDb guardDb, IGuardEventSink events) : ITransientDependency, IOrganizationImport
{
    public async Task<Guid> EnsureAsync(Guid? known, string name, IReadOnlyCollection<Guid> members, CancellationToken cancellationToken)
    {
        string wanted = name.Trim() is { Length: > 0 } trimmed ? trimmed[..Math.Min(trimmed.Length, 100)] : "Organization";
        (Group group, bool created, bool changed) = await guardDb.RunAsync(async db =>
        {
            Group? group = known is { } id ? await db.Groups.FirstOrDefaultAsync(g => g.Id == id && g.Kind == GroupKinds.Organization, cancellationToken) : null;
            bool created = false;
            if (group is null)
            {
                // A group of another kind may have the name already: the organization then gets a name of its own.
                foreach (string candidate in new[] { wanted, $"{wanted} (organization)" })
                {
                    string normalized = GuardConstants.Normalize(candidate);
                    Group? same = await db.Groups.FirstOrDefaultAsync(g => g.DirectoryId == GuardConstants.InternalDirectoryId && g.NormalizedName == normalized,
                        cancellationToken);
                    if (same is { Kind: GroupKinds.Organization })
                    {
                        group = same;
                        break;
                    }

                    if (same is null)
                    {
                        group = db.Groups.Add(new Group(Guid.NewGuid(), GuardConstants.InternalDirectoryId, candidate, isLocal: true) { Kind = GroupKinds.Organization }).Entity;
                        created = true;
                        break;
                    }
                }

                if (group is null)
                {
                    throw new Volo.Abp.UserFriendlyException($"The internal directory has groups called '{wanted}' and '{wanted} (organization)' already.");
                }
            }

            List<Guid> wantedMembers = [.. members.Distinct()];
            List<Guid> accounts = await db.Accounts.Where(a => wantedMembers.Contains(a.Id)).Select(a => a.Id).ToListAsync(cancellationToken);
            HashSet<Guid> have = [.. await db.Memberships.Where(m => m.GroupId == group.Id && m.MemberType == MemberType.Account && m.Source == MembershipSource.Manual)
                .Select(m => m.MemberId).ToListAsync(cancellationToken)];
            bool changed = false;
            foreach (Guid account in accounts.Where(a => !have.Contains(a)))
            {
                db.Memberships.Add(new GroupMembership(Guid.NewGuid(), group.Id, MemberType.Account, account, MembershipSource.Manual));
                changed = true;
            }

            await db.SaveChangesAsync(cancellationToken);
            // In the import's unit of work: the events commit with it.
            if (created)
            {
                await GuardEvents.PublishAsync(events, new GroupCreatedEto(group.Id, group.Name), cancellationToken);
            }

            if (changed)
            {
                await GuardEvents.PublishAsync(events, new MembershipChangedEto(group.Id, group.Name), cancellationToken);
            }

            return (group, created, changed);
        }, requiresNew: true, cancellationToken, isTransactional: true);

        return group.Id;
    }
}
