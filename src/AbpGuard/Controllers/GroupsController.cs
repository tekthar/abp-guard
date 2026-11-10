using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AbpGuard.Data;
using AbpGuard.Domain;
using AbpGuard.Services;
using AbpGuard.Acting;
using Volo.Abp;
using Volo.Abp.Domain.Entities;

namespace AbpGuard.Controllers;

[Route("api/guard/groups")]
[Authorize(Policy = GuardPolicies.Admin)]
public class GroupsController(GuardDb guardDb, MembershipGraph graph, SecurityLog audit, Microsoft.Extensions.Options.IOptions<GuardOptions> options) : GuardControllerBase
{
    /// <summary>What Guard's messages call the host (Texts.ProductName).</summary>
    private string Product => options.Value.Texts.Product();

    [HttpGet]
    public Task<List<GroupDto>> List([FromQuery] string? search, [FromQuery] Guid? directoryId, [FromQuery] string? kind, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db =>
        {
            IQueryable<Group> query = db.Groups.AsNoTracking();
            if (!string.IsNullOrWhiteSpace(kind))
            {
                query = query.Where(g => g.Kind == kind);
            }

            if (!string.IsNullOrWhiteSpace(search))
            {
                string s = GuardConstants.Normalize(search);
                query = query.Where(g => g.NormalizedName.Contains(s));
            }

            if (directoryId is { } d)
            {
                query = query.Where(g => g.DirectoryId == d);
            }

            List<Group> groups = await query.OrderBy(g => g.Name).Take(500).ToListAsync(cancellationToken);
            return await ToDtosAsync(db, groups, cancellationToken);
        }, cancellationToken: cancellationToken);

    [HttpGet("{id:guid}")]
    public Task<GroupDetailDto> Get(Guid id, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db =>
        {
            Group group = await db.Groups.AsNoTracking().FirstOrDefaultAsync(g => g.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Group), id);
            Dictionary<Guid, string> directories = await db.Directories.ToDictionaryAsync(d => d.Id, d => d.Name, cancellationToken);
            bool writable = IsWritable(group);

            List<GroupMembership> memberships = await db.Memberships.AsNoTracking().Where(m => m.GroupId == id).ToListAsync(cancellationToken);
            List<Guid> userIds = memberships.Where(m => m.MemberType == MemberType.DirectoryUser).Select(m => m.MemberId).ToList();
            List<Guid> accountIds = memberships.Where(m => m.MemberType == MemberType.Account).Select(m => m.MemberId).ToList();
            List<Guid> groupIds = memberships.Where(m => m.MemberType == MemberType.Group).Select(m => m.MemberId).ToList();
            Dictionary<Guid, DirectoryUser> users = await db.DirectoryUsers.AsNoTracking().Where(u => userIds.Contains(u.Id)).ToDictionaryAsync(u => u.Id, cancellationToken);
            Dictionary<Guid, Account> accounts = await db.Accounts.AsNoTracking().Where(a => accountIds.Contains(a.Id)).ToDictionaryAsync(a => a.Id, cancellationToken);
            Dictionary<Guid, Group> childGroups = await db.Groups.AsNoTracking().Where(g => groupIds.Contains(g.Id)).ToDictionaryAsync(g => g.Id, cancellationToken);
            // Synced memberships point at a directory record; show the account that record belongs to.
            Dictionary<Guid, Account> accountsByRecord = await db.Accounts.AsNoTracking()
                .Where(a => a.DirectoryUserId != null && userIds.Contains(a.DirectoryUserId.Value))
                .ToDictionaryAsync(a => a.DirectoryUserId!.Value, cancellationToken);

            List<GroupMemberDto> members = [];
            foreach (GroupMembership m in memberships)
            {
                bool removable = writable && m.Source == MembershipSource.Manual;
                switch (m.MemberType)
                {
                    case MemberType.DirectoryUser when users.TryGetValue(m.MemberId, out DirectoryUser? u):
                        // A shadowed record (its username is owned by an earlier directory) has no account of its own.
                        Guid memberId = accountsByRecord.TryGetValue(u.Id, out Account? owner) ? owner.Id : u.Id;
                        string? display = owner is null ? $"{u.DisplayName} (shadowed)" : u.DisplayName;
                        members.Add(new GroupMemberDto("Account", memberId, u.Username, display, directories.GetValueOrDefault(u.DirectoryId, "?"), m.Source.ToString(), removable));
                        break;
                    case MemberType.Account when accounts.TryGetValue(m.MemberId, out Account? a):
                        members.Add(new GroupMemberDto("Account", a.Id, a.Username, a.DisplayName, directories.GetValueOrDefault(a.DirectoryId, "?"), m.Source.ToString(), removable));
                        break;
                    case MemberType.Group when childGroups.TryGetValue(m.MemberId, out Group? g):
                        members.Add(new GroupMemberDto("Group", g.Id, g.Name, g.Description, directories.GetValueOrDefault(g.DirectoryId, "?"), m.Source.ToString(), removable));
                        break;
                }
            }

            List<Guid> parentIds = await db.Memberships.AsNoTracking()
                .Where(m => m.MemberType == MemberType.Group && m.MemberId == id)
                .Select(m => m.GroupId)
                .Distinct()
                .ToListAsync(cancellationToken);
            List<Group> parents = await db.Groups.AsNoTracking().Where(g => parentIds.Contains(g.Id)).OrderBy(g => g.Name).ToListAsync(cancellationToken);

            List<EffectiveMemberDto> effective = (await graph.GetEffectiveMembersAsync(db, id, cancellationToken))
                .Select(e => new EffectiveMemberDto(e.Account.Id, e.Account.Username, e.Account.DisplayName, e.Path))
                .ToList();

            GroupDto dto = (await ToDtosAsync(db, [group], cancellationToken))[0];
            return new GroupDetailDto(
                dto,
                members.OrderBy(m => m.MemberType).ThenBy(m => m.Name).ToList(),
                await ToDtosAsync(db, parents, cancellationToken),
                effective);
        }, cancellationToken: cancellationToken);

    /// <summary>A group to make in Guard: standard, or an organization with attributes and email domains.</summary>
    public sealed record CreateGroupInput(string Name, string? Description, Guid? DirectoryId, string? Kind = null, Dictionary<string, string>? Attributes = null,
        List<string>? EmailDomains = null);

    /// <summary>What can change on a group made in Guard: its name and description, and an organization's attributes and domains.</summary>
    public sealed record UpdateGroupInput(string Name, string? Description, Dictionary<string, string>? Attributes = null, List<string>? EmailDomains = null);

    [HttpPost]
    [StepUp]
    public async Task<GroupDto> Create([FromBody] CreateGroupInput input, CancellationToken cancellationToken)
    {
        Guid directoryId = input.DirectoryId ?? GuardConstants.InternalDirectoryId;
        if (directoryId != GuardConstants.InternalDirectoryId)
        {
            throw new UserFriendlyException("In this PoC, groups are created in the internal directory. Nest a synced group inside it to reuse a directory group.");
        }

        string kind = input.Kind ?? GroupKinds.Standard;
        if (kind is not (GroupKinds.Standard or GroupKinds.Organization))
        {
            throw new UserFriendlyException($"Groups made here are standard groups or organizations; {Product} keeps directory and OU groups itself.");
        }

        if (string.IsNullOrWhiteSpace(input.Name) || input.Name.Trim().Length > 128)
        {
            throw new UserFriendlyException("Group names are 1–128 characters.");
        }

        (Dictionary<string, string> attributes, List<string> domains) = kind == GroupKinds.Organization
            ? Organization(input.Attributes, input.EmailDomains)
            : ([], []);

        GroupDto dto = await guardDb.RunAsync(async db =>
        {
            string normalized = GuardConstants.Normalize(input.Name);
            if (await db.Groups.AnyAsync(g => g.DirectoryId == directoryId && g.NormalizedName == normalized, cancellationToken))
            {
                throw new UserFriendlyException($"The internal directory already has a group called '{input.Name.Trim()}'.");
            }

            Group group = new(Guid.NewGuid(), directoryId, input.Name, isLocal: true)
            {
                Description = input.Description?.Trim(),
                Kind = kind,
                Attributes = attributes,
                EmailDomains = domains,
            };
            db.Groups.Add(group);
            audit.Add(db, SecurityAuditTypes.GroupCreated, Target(group), new { kind, emailDomains = domains });
            await db.SaveChangesAsync(cancellationToken);
            if (kind == GroupKinds.Organization)
            {
                await Organizations.ApplyDomainsAsync(db, cancellationToken);
            }

            return (await ToDtosAsync(db, [group], cancellationToken))[0];
        }, requiresNew: true, cancellationToken);

        await PublishAsync([new GroupCreatedEto(dto.Id, dto.Name)]);
        return dto;
    }

    /// <summary>Renames a group made in Guard, changes its description, and an organization's attributes and domains.</summary>
    [HttpPut("{id:guid}")]
    [StepUp]
    public async Task<GroupDto> Update(Guid id, [FromBody] UpdateGroupInput input, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(input.Name) || input.Name.Trim().Length > 128)
        {
            throw new UserFriendlyException("Group names are 1–128 characters.");
        }

        GroupDto dto = await guardDb.RunAsync(async db =>
        {
            Group group = await db.Groups.FirstOrDefaultAsync(g => g.Id == id, cancellationToken) ?? throw new EntityNotFoundException(typeof(Group), id);
            if (!IsWritable(group))
            {
                throw new UserFriendlyException(group.Computed
                    ? $"{Product} keeps '{group.Name}' in step with its directory; change the directory instead."
                    : $"'{group.Name}' is synced from a directory. Change it there.");
            }

            string normalized = GuardConstants.Normalize(input.Name);
            if (await db.Groups.AnyAsync(g => g.Id != id && g.DirectoryId == group.DirectoryId && g.NormalizedName == normalized, cancellationToken))
            {
                throw new UserFriendlyException($"There's already a group called '{input.Name.Trim()}'.");
            }

            string oldName = group.Name;
            List<string> oldDomains = [.. group.EmailDomains];
            group.SetName(input.Name);
            group.Description = input.Description?.Trim();
            if (group.Kind == GroupKinds.Organization)
            {
                (group.Attributes, group.EmailDomains) = Organization(input.Attributes, input.EmailDomains);
            }

            // An organization's domains decide who is in it, and so who is a customer where it's granted.
            audit.Add(db, SecurityAuditTypes.GroupUpdated, Target(group), new
            {
                name = oldName == group.Name ? null : new { before = oldName, after = group.Name },
                emailDomains = oldDomains.SequenceEqual(group.EmailDomains) ? null : new { before = oldDomains, after = group.EmailDomains },
            });
            await db.SaveChangesAsync(cancellationToken);
            if (group.Kind == GroupKinds.Organization)
            {
                await Organizations.ApplyDomainsAsync(db, cancellationToken);
            }

            return (await ToDtosAsync(db, [group], cancellationToken))[0];
        }, requiresNew: true, cancellationToken);

        await PublishAsync([new MembershipChangedEto(id, dto.Name)]);
        return dto;
    }

    public sealed record GroupTwoFactorInput(string? Mode);

    /// <summary>
    /// Sets whether the group's members are asked for a second factor: <c>off</c>, <c>optional</c>,
    /// <c>required</c> or <c>strong</c>. A person follows the strictest of all their groups, nested and synced ones too.
    /// </summary>
    [HttpPut("{id:guid}/two-factor")]
    [StepUp]
    public Task<GroupDto> SetTwoFactor(Guid id, [FromBody] GroupTwoFactorInput input, CancellationToken cancellationToken)
    {
        if (input.Mode is not { } mode || !TwoFactorModes.All.Contains(mode))
        {
            throw new UserFriendlyException($"The mode is one of {string.Join(", ", TwoFactorModes.All)}.");
        }

        return guardDb.RunAsync(async db =>
        {
            Group group = await db.Groups.FirstOrDefaultAsync(g => g.Id == id, cancellationToken) ?? throw new EntityNotFoundException(typeof(Group), id);
            if (group.TwoFactor != mode)
            {
                audit.Add(db, SecurityAuditTypes.GroupTwoFactor, Target(group), new { before = group.TwoFactor, after = mode });
                group.TwoFactor = mode;
                await db.SaveChangesAsync(cancellationToken);
            }

            return (await ToDtosAsync(db, [group], cancellationToken))[0];
        }, requiresNew: true, cancellationToken);
    }

    [HttpDelete("{id:guid}")]
    [StepUp]
    public async Task<NoContentResult> Delete(Guid id, CancellationToken cancellationToken)
    {
        if (id == GuardConstants.AdminsGroupId || id == GuardConstants.UsersGroupId)
        {
            throw new UserFriendlyException($"{options.Value.AdminsGroupName} and {options.Value.Seed.UsersGroupName} are system groups and can't be deleted.");
        }

        await guardDb.RunAsync(async db =>
        {
            Group group = await db.Groups.FirstOrDefaultAsync(g => g.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Group), id);
            if (!IsWritable(group))
            {
                throw new UserFriendlyException(group.Computed
                    ? $"{Product} keeps '{group.Name}' in step with its directory: it goes when the directory (or the OU in its settings) does."
                    : $"'{group.Name}' is synced from a directory. Delete it there.");
            }

            int memberships = await db.Memberships.Where(m => m.GroupId == id || (m.MemberType == MemberType.Group && m.MemberId == id)).ExecuteDeleteAsync(cancellationToken);
            db.Groups.Remove(group);
            audit.Add(db, SecurityAuditTypes.GroupDeleted, Target(group), new { kind = group.Kind, memberships });
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken, isTransactional: true);

        return NoContent();
    }

    public sealed record AddMemberInput(Guid? AccountId, Guid? GroupId);

    [HttpPost("{id:guid}/members")]
    [StepUp]
    public async Task<NoContentResult> AddMember(Guid id, [FromBody] AddMemberInput input, CancellationToken cancellationToken)
    {
        if (input.AccountId is null == input.GroupId is null)
        {
            throw new UserFriendlyException("Give either an accountId or a groupId.");
        }

        string groupName = await guardDb.RunAsync(async db =>
        {
            Group group = await db.Groups.FirstOrDefaultAsync(g => g.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Group), id);
            if (!IsWritable(group))
            {
                throw new UserFriendlyException(group.Computed
                    ? $"{Product} works out who is in '{group.Name}' from its directory. Nest it inside another group instead."
                    : $"'{group.Name}' is synced from a directory, so its members are managed there. Nest it inside an internal group instead.");
            }

            (MemberType type, Guid memberId) = input.AccountId is { } accountId
                ? (MemberType.Account, accountId)
                : (MemberType.Group, input.GroupId!.Value);

            if (type == MemberType.Account && !await db.Accounts.AnyAsync(a => a.Id == memberId, cancellationToken))
            {
                throw new EntityNotFoundException(typeof(Account), memberId);
            }

            if (type == MemberType.Group)
            {
                if (!await db.Groups.AnyAsync(g => g.Id == memberId, cancellationToken))
                {
                    throw new EntityNotFoundException(typeof(Group), memberId);
                }

                List<string>? cycle = await graph.FindCycleAsync(db, id, memberId, cancellationToken);
                if (cycle is not null)
                {
                    throw new UserFriendlyException($"That would create a loop: {string.Join(" → ", cycle)}.");
                }
            }

            if (!await db.Memberships.AnyAsync(m => m.GroupId == id && m.MemberType == type && m.MemberId == memberId && m.Source == MembershipSource.Manual, cancellationToken))
            {
                db.Memberships.Add(new GroupMembership(Guid.NewGuid(), id, type, memberId, MembershipSource.Manual));
                audit.Add(db, SecurityAuditTypes.MembershipAdded, await MemberTargetAsync(db, type, memberId, cancellationToken), new { group = Target(group) });
                await db.SaveChangesAsync(cancellationToken);
            }

            return group.Name;
        }, requiresNew: true, cancellationToken, isTransactional: true);

        await PublishAsync([new MembershipChangedEto(id, groupName)]);
        return NoContent();
    }

    [HttpDelete("{id:guid}/members/{memberType}/{memberId:guid}")]
    [StepUp]
    public async Task<NoContentResult> RemoveMember(Guid id, string memberType, Guid memberId, CancellationToken cancellationToken)
    {
        string groupName = await guardDb.RunAsync(async db =>
        {
            Group group = await db.Groups.FirstOrDefaultAsync(g => g.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Group), id);

            MemberType[] types = memberType.Equals("Group", StringComparison.OrdinalIgnoreCase)
                ? [MemberType.Group]
                : [MemberType.Account, MemberType.DirectoryUser];
            // An account can be a member through a Manual row (its account id) or a Directory row (its directory record).
            Guid? recordId = types.Contains(MemberType.Account)
                ? await db.Accounts.Where(a => a.Id == memberId).Select(a => a.DirectoryUserId).FirstOrDefaultAsync(cancellationToken)
                : null;
            List<GroupMembership> rows = await db.Memberships
                .Where(m => m.GroupId == id && types.Contains(m.MemberType) && (m.MemberId == memberId || (recordId != null && m.MemberId == recordId)))
                .ToListAsync(cancellationToken);

            GroupMembership? manual = rows.FirstOrDefault(r => r.Source == MembershipSource.Manual);
            if (manual is null)
            {
                if (rows.Any(r => r.Source == MembershipSource.Domain))
                {
                    throw new UserFriendlyException($"This person is in {group.Name} because of their email's domain. Change the organization's domains instead.");
                }

                if (rows.Count > 0)
                {
                    string directory = await db.Directories.Where(d => d.Id == group.DirectoryId).Select(d => d.Name).FirstAsync(cancellationToken);
                    throw new UserFriendlyException($"This membership comes from {directory}. Change it there; the next sync will update {Product}.");
                }

                throw new EntityNotFoundException(typeof(GroupMembership), memberId);
            }

            db.Memberships.Remove(manual);
            audit.Add(db, SecurityAuditTypes.MembershipRemoved,
                await MemberTargetAsync(db, types.Contains(MemberType.Group) ? MemberType.Group : MemberType.Account, memberId, cancellationToken), new { group = Target(group) });
            await db.SaveChangesAsync(cancellationToken);
            return group.Name;
        }, requiresNew: true, cancellationToken);

        await PublishAsync([new MembershipChangedEto(id, groupName)]);
        return NoContent();
    }

    private static AuditTarget Target(Group group) => new("Group", group.Id, group.Name);

    /// <summary>Whose rights a membership changes: the account, or the group nested in another.</summary>
    private static async Task<AuditTarget> MemberTargetAsync(GuardDbContext db, MemberType type, Guid id, CancellationToken cancellationToken) =>
        type == MemberType.Group
            ? new AuditTarget("Group", id, await db.Groups.Where(g => g.Id == id).Select(g => g.Name).FirstOrDefaultAsync(cancellationToken))
            : new AuditTarget("Account", id, await db.Accounts.Where(a => a.Id == id).Select(a => a.Username).FirstOrDefaultAsync(cancellationToken));

    private static bool IsWritable(Group group) => !group.Computed && (group.IsLocal || group.DirectoryId == GuardConstants.InternalDirectoryId);

    /// <summary>An organization's attributes (at most 20, names up to 64 characters, values up to 500) and email domains (at most 20).</summary>
    private static (Dictionary<string, string> Attributes, List<string> Domains) Organization(Dictionary<string, string>? attributes, List<string>? domains)
    {
        Dictionary<string, string> clean = new(StringComparer.Ordinal);
        foreach ((string name, string value) in attributes ?? [])
        {
            if (string.IsNullOrWhiteSpace(name) || name.Trim().Length > 64 || (value ?? "").Length > 500)
            {
                throw new UserFriendlyException("An attribute has a name of 1–64 characters and a value of at most 500.");
            }

            clean[name.Trim()] = value?.Trim() ?? "";
        }

        List<string> normalized = [];
        foreach (string domain in domains ?? [])
        {
            normalized.Add(Organizations.NormalizeDomain(domain) ?? throw new UserFriendlyException($"'{domain}' isn't an email domain, such as example.com."));
        }

        return clean.Count > 20 || normalized.Count > 20
            ? throw new UserFriendlyException("An organization has at most 20 attributes and 20 email domains.")
            : (clean, normalized.Distinct().ToList());
    }

    private static async Task<List<GroupDto>> ToDtosAsync(GuardDbContext db, List<Group> groups, CancellationToken cancellationToken)
    {
        List<Guid> ids = groups.Select(g => g.Id).ToList();
        Dictionary<Guid, string> directories = await db.Directories.ToDictionaryAsync(d => d.Id, d => d.Name, cancellationToken);
        var counts = await db.Memberships.AsNoTracking()
            .Where(m => ids.Contains(m.GroupId))
            .GroupBy(m => new { m.GroupId, IsGroup = m.MemberType == MemberType.Group })
            .Select(x => new { x.Key.GroupId, x.Key.IsGroup, Count = x.Select(m => m.MemberId).Distinct().Count() })
            .ToListAsync(cancellationToken);

        // A directory's group has no rows: count the active accounts its directory owns.
        List<Guid> directoryGroupDirectories = groups.Where(g => g.Kind == GroupKinds.Directory).Select(g => g.DirectoryId).ToList();
        Dictionary<Guid, int> owned = directoryGroupDirectories.Count == 0 ? [] : await db.Accounts.AsNoTracking()
            .Where(a => a.Status == AccountStatus.Active && directoryGroupDirectories.Contains(a.DirectoryId))
            .GroupBy(a => a.DirectoryId).ToDictionaryAsync(x => x.Key, x => x.Count(), cancellationToken);
        return groups.Select(g => new GroupDto(
                g.Id, g.Name, g.Description, g.DirectoryId, directories.GetValueOrDefault(g.DirectoryId, "?"), g.IsLocal, IsWritable(g),
                g.Kind == GroupKinds.Directory ? owned.GetValueOrDefault(g.DirectoryId) : counts.Where(c => c.GroupId == g.Id && !c.IsGroup).Sum(c => c.Count),
                counts.Where(c => c.GroupId == g.Id && c.IsGroup).Sum(c => c.Count),
                g.Kind, g.Computed, g.Attributes, g.EmailDomains, g.TwoFactor))
            .ToList();
    }
}
