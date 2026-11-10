using Microsoft.EntityFrameworkCore;
using AbpGuard.Controllers;
using AbpGuard.Data;
using AbpGuard.Domain;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>
/// Groups from an import: the group the import made before for this source and name (found by its external
/// id), else the only standard or OU group in Guard with that name (a directory's, used as it is: its members are the
/// directory's business), else a new standard group in the internal directory. An imported group's members are the
/// source's, as <see cref="MembershipSource.Import"/> members; members an admin added by hand stay.
/// </summary>
[ExposeServices(typeof(GroupImport), typeof(IGroupImport))]
public class GroupImport(GuardDb guardDb, IGuardEventSink events) : ITransientDependency, IGroupImport
{
    private static string ExternalId(string source, string name) => $"import:{source}:{GuardConstants.Normalize(name.Trim())}";

    public Task<ImportedGroup?> FindAsync(string source, string name, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(db => FindAsync(db, source, name, cancellationToken), cancellationToken: cancellationToken);

    private static async Task<ImportedGroup?> FindAsync(GuardDbContext db, string source, string name, CancellationToken cancellationToken)
    {
        string external = ExternalId(source, name);
        if (await db.Groups.AsNoTracking().FirstOrDefaultAsync(g => g.DirectoryId == GuardConstants.InternalDirectoryId && g.ExternalId == external, cancellationToken)
            is { } made)
        {
            return new ImportedGroup(made.Id, made.Name, Imported: true);
        }

        string normalized = GuardConstants.Normalize(name.Trim());
        List<Group> same = await db.Groups.AsNoTracking()
            .Where(g => g.NormalizedName == normalized && (g.Kind == GroupKinds.Standard || g.Kind == GroupKinds.Ou)).Take(2).ToListAsync(cancellationToken);
        return same is [var only] ? new ImportedGroup(only.Id, only.Name, Imported: false) : null;
    }

    public async Task<ImportedGroup> EnsureAsync(string source, string name, IReadOnlyCollection<Guid> members, CancellationToken cancellationToken = default)
    {
        string wanted = name.Trim() is { Length: > 0 } trimmed ? trimmed[..Math.Min(trimmed.Length, 200)] : "Imported group";
        return await guardDb.RunAsync(async db =>
        {
            if (await FindAsync(db, source, wanted, cancellationToken) is { Imported: false } existing)
            {
                return existing;
            }

            string external = ExternalId(source, wanted);
            Group? group = await db.Groups.FirstOrDefaultAsync(g => g.DirectoryId == GuardConstants.InternalDirectoryId && g.ExternalId == external, cancellationToken);
            bool created = false;
            if (group is null)
            {
                // Two groups elsewhere may share the name (so neither is the one), or the internal directory may hold
                // one of another kind: the imported group then gets a name of its own.
                foreach (string candidate in new[] { wanted, $"{wanted} (imported)" }.Concat(Enumerable.Range(2, 8).Select(n => $"{wanted} (imported {n})")))
                {
                    string normalized = GuardConstants.Normalize(candidate);
                    if (!await db.Groups.AnyAsync(g => g.DirectoryId == GuardConstants.InternalDirectoryId && g.NormalizedName == normalized, cancellationToken))
                    {
                        group = db.Groups.Add(new Group(Guid.NewGuid(), GuardConstants.InternalDirectoryId, candidate, isLocal: true)
                        {
                            ExternalId = external,
                            Description = "Imported, with its members as the source has them.",
                        }).Entity;
                        created = true;
                        break;
                    }
                }

                if (group is null)
                {
                    throw new Volo.Abp.UserFriendlyException($"The internal directory has groups called '{wanted}' and '{wanted} (imported)' already.");
                }
            }

            List<Guid> wantedMembers = [.. members.Distinct()];
            HashSet<Guid> accounts = [.. await db.Accounts.Where(a => wantedMembers.Contains(a.Id)).Select(a => a.Id).ToListAsync(cancellationToken)];
            List<GroupMembership> have = await db.Memberships
                .Where(m => m.GroupId == group.Id && m.MemberType == MemberType.Account && m.Source == MembershipSource.Import).ToListAsync(cancellationToken);
            bool changed = false;
            foreach (Guid account in accounts.Where(a => have.All(m => m.MemberId != a)))
            {
                db.Memberships.Add(new GroupMembership(Guid.NewGuid(), group.Id, MemberType.Account, account, MembershipSource.Import));
                changed = true;
            }

            foreach (GroupMembership gone in have.Where(m => !accounts.Contains(m.MemberId)))
            {
                db.Memberships.Remove(gone);
                changed = true;
            }

            await db.SaveChangesAsync(cancellationToken);
            // In the import's unit of work: the events commit with it, as OrganizationImport's do.
            if (created)
            {
                await GuardEvents.PublishAsync(events, new GroupCreatedEto(group.Id, group.Name), cancellationToken);
            }

            if (changed)
            {
                await GuardEvents.PublishAsync(events, new MembershipChangedEto(group.Id, group.Name), cancellationToken);
            }

            return new ImportedGroup(group.Id, group.Name, Imported: true);
        }, requiresNew: true, cancellationToken, isTransactional: true);
    }
}
