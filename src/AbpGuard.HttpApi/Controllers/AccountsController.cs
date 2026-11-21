using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using AbpGuard.Domain;
using AbpGuard.Services;
using AbpGuard.Acting;
using Casl;
using AbpGuard.Data;
using Volo.Abp;
using Volo.Abp.Application.Dtos;
using Volo.Abp.Domain.Entities;

namespace AbpGuard.Controllers;

/// <summary>
/// Account APIs authorized row by row with CASL .NET: the list is filtered in SQL with AccessibleBy, and each
/// action is checked against the account it targets. Admins see everything through "manage all".
/// </summary>
[Route("api/guard/accounts")]
[Authorize]
public class AccountsController(GuardDb guardDb, MembershipGraph graph, AccountProjector projector, AccountMergeService merges, AccountEmailService emails,
    SecurityLog audit, AccountSessions sessions, Microsoft.Extensions.Options.IOptions<GuardOptions> options, SelfService self)
    : GuardControllerBase
{
    /// <summary>The accounts the caller may read, by username, at most 500: what pickers search. A list that pages takes <see cref="Page"/>.</summary>
    [HttpGet]
    public async Task<List<AccountDto>> List([FromQuery] string? search, [FromQuery] string? status, CancellationToken cancellationToken)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
        Ensure(ability, "read", "Account");
        return await guardDb.RunAsync(async db =>
        {
            Dictionary<Guid, string> directories = await db.Directories.ToDictionaryAsync(d => d.Id, d => d.Name, cancellationToken);
            return (await Filtered(db, ability, search, status).OrderBy(a => a.Username).Take(500).ToListAsync(cancellationToken))
                .Select(a => AccountDto.From(a, directories.GetValueOrDefault(a.DirectoryId, "?")))
                .ToList();
        }, cancellationToken: cancellationToken);
    }

    /// <summary>
    /// A page of the accounts the caller may read, in ABP's shape: <c>totalCount</c> and <c>items</c>, the list's search,
    /// status and directory, sorted by username, displayName, email, status, directory, createdAt or lastLoginAt
    /// (username unless asked), and grouped by status or directory with every group's total.
    /// </summary>
    [HttpGet("page")]
    public async Task<GuardPagedResultDto<AccountDto>> Page([FromQuery] AccountPageInput input, CancellationToken cancellationToken)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
        Ensure(ability, "read", "Account");
        string? sorting = GuardPaging.Grouped(input.GroupBy, input.Sorting, "status", "directory");
        return await guardDb.RunAsync(async db =>
        {
            IQueryable<Account> query = Filtered(db, ability, input.Filter, input.Status, input.DirectoryId);
            int total = await query.CountAsync(cancellationToken);
            List<Account> page = await GuardPaging.Sort(query, sorting, AccountSorts(db), "username", a => a.Id)
                .Skip(input.SkipCount).Take(input.MaxResultCount).ToListAsync(cancellationToken);
            Dictionary<Guid, string> directories = await db.Directories.ToDictionaryAsync(d => d.Id, d => d.Name, cancellationToken);
            List<ListGroupDto>? groups = input.GroupBy?.Trim().ToLowerInvariant() switch
            {
                "status" => (await query.GroupBy(a => a.Status).Select(g => new { g.Key, Count = g.Count() }).ToListAsync(cancellationToken))
                    .OrderBy(g => g.Key).Select(g => new ListGroupDto(g.Key.ToString(), g.Key.ToString(), g.Count)).ToList(),
                "directory" => (await query.GroupBy(a => a.DirectoryId).Select(g => new { g.Key, Count = g.Count() }).ToListAsync(cancellationToken))
                    .Select(g => new ListGroupDto(g.Key.ToString(), directories.GetValueOrDefault(g.Key, "?"), g.Count)).OrderBy(g => g.Label, StringComparer.Ordinal).ToList(),
                _ => null,
            };
            return new GuardPagedResultDto<AccountDto>(total, page.Select(a => AccountDto.From(a, directories.GetValueOrDefault(a.DirectoryId, "?"))).ToList(), groups);
        }, cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Every account the list would show (its search, status, directory and sorting), as CSV, at most 100,000 rows. A
    /// list of people is personal data: a step-up first, and the export is in the security log with its filters.
    /// </summary>
    [HttpGet("export")]
    [StepUp(StepUpCategories.Exports)]
    public async Task<FileContentResult> Export([FromQuery] AccountPageInput input, CancellationToken cancellationToken)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
        Ensure(ability, "read", "Account");
        string? sorting = GuardPaging.Grouped(input.GroupBy, input.Sorting, "status", "directory");
        byte[] csv = await guardDb.RunAsync(async db =>
        {
            List<Account> rows = await GuardPaging.Sort(Filtered(db, ability, input.Filter, input.Status, input.DirectoryId), sorting, AccountSorts(db), "username", a => a.Id)
                .Take(GuardCsv.MaxRows).ToListAsync(cancellationToken);
            Dictionary<Guid, string> directories = await db.Directories.ToDictionaryAsync(d => d.Id, d => d.Name, cancellationToken);
            audit.Add(db, SecurityAuditTypes.AccountsExported, new AuditTarget("Account", null, "accounts"),
                new { filter = input.Filter, status = input.Status, directoryId = input.DirectoryId, sorting, rows = rows.Count });
            await db.SaveChangesAsync(cancellationToken);
            return GuardCsv.Write(["Username", "Display name", "Email", "Directory", "Status", "Last sign-in", "Created"],
                rows.Select(a => (IReadOnlyList<string?>)[a.Username, a.DisplayName, a.MailTo ?? a.Email, directories.GetValueOrDefault(a.DirectoryId), a.Status.ToString(),
                    GuardCsv.Time(a.LastLoginAt), GuardCsv.Time(a.CreatedAt)]));
        }, requiresNew: true, cancellationToken, isTransactional: true);
        return File(csv, "text/csv; charset=utf-8", $"accounts-{DateTime.UtcNow:yyyy-MM-dd}.csv");
    }

    private static Dictionary<string, System.Linq.Expressions.LambdaExpression> AccountSorts(GuardDbContext db) => new(StringComparer.OrdinalIgnoreCase)
    {
        ["username"] = GuardPaging.By<Account, string>(a => a.Username),
        ["displayName"] = GuardPaging.By<Account, string>(a => a.DisplayName),
        ["email"] = GuardPaging.By<Account, string?>(a => a.Email),
        ["status"] = GuardPaging.By<Account, AccountStatus>(a => a.Status),
        ["directory"] = GuardPaging.By<Account, string?>(a => db.Directories.Where(d => d.Id == a.DirectoryId).Select(d => d.Name).FirstOrDefault()),
        ["createdAt"] = GuardPaging.By<Account, DateTime>(a => a.CreatedAt),
        ["lastLoginAt"] = GuardPaging.By<Account, DateTime?>(a => a.LastLoginAt),
    };

    /// <summary>The accounts the ability may read (filtered in SQL), with the list's search, status and directory.</summary>
    private static IQueryable<Account> Filtered(GuardDbContext db, Casl.Ability ability, string? search, string? status, Guid? directoryId = null)
    {
        IQueryable<Account> query = db.Accounts.AsNoTracking().AccessibleBy(ability, "read");
        if (!string.IsNullOrWhiteSpace(search))
        {
            string s = GuardConstants.Normalize(search), like = SqlLike.Containing(s);
            query = query.Where(a => a.NormalizedUsername.Contains(s) || EF.Functions.ILike(a.DisplayName, like) || (a.OtherNames != null && EF.Functions.ILike(a.OtherNames, like)) || (a.Email != null && EF.Functions.ILike(a.Email, like)));
        }

        if (Enum.TryParse(status, ignoreCase: true, out AccountStatus parsed))
        {
            query = query.Where(a => a.Status == parsed);
        }

        if (directoryId is { } directory)
        {
            query = query.Where(a => a.DirectoryId == directory);
        }

        return query;
    }

    [HttpGet("{id:guid}")]
    public async Task<AccountDetailDto> Get(Guid id, CancellationToken cancellationToken)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
        List<AccountMergeDto> merged = await merges.ListAsync(id, 50, cancellationToken);
        (AccountDetailDto detail, Account target) = await guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Account), id);
            Ensure(ability, "read", account);
            Dictionary<Guid, UserDirectory> directories = await db.Directories.ToDictionaryAsync(d => d.Id, cancellationToken);

            List<IdentityDto> identities = (await db.DirectoryUsers.AsNoTracking()
                    .Where(u => u.NormalizedUsername == account.NormalizedUsername)
                    .ToListAsync(cancellationToken))
                .Select(u => new IdentityDto(
                    u.DirectoryId, directories[u.DirectoryId].Name, directories[u.DirectoryId].Order, u.ExternalId, u.Username,
                    u.DisplayName, u.Email, u.IsActive && directories[u.DirectoryId].IsActive, u.Id == account.DirectoryUserId, u.LastSyncedAt))
                .OrderBy(i => i.DirectoryOrder)
                .ToList();

            List<EffectiveGroupDto> groups = (await graph.GetEffectiveGroupsAsync(db, account, cancellationToken))
                .Select(g => new EffectiveGroupDto(g.Group.Id, g.Group.Name, g.Group.DirectoryId, directories[g.Group.DirectoryId].Name, g.Direct, g.Path))
                .ToList();

            string? into = account.MergedIntoId is { } survivor ? await db.Accounts.Where(a => a.Id == survivor).Select(a => a.Username).FirstOrDefaultAsync(cancellationToken) : null;
            return (new AccountDetailDto(AccountDto.From(account, directories[account.DirectoryId].Name), identities, groups,
                await AccountEmailService.LoadAsync(db, id, cancellationToken), merged, into), account);
        }, cancellationToken: cancellationToken);
        return detail with { Can = await CanAsync(ability, target, cancellationToken) };
    }

    /// <summary>What the caller may do to the account, by the same rules its actions check (<see cref="AccountCanDto"/>).</summary>
    private async Task<AccountCanDto> CanAsync(Casl.Ability ability, Account account, CancellationToken cancellationToken)
    {
        GuardFeatures features = HttpContext.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<GuardOptions>>().Value.Features;
        bool admin = ability.Can("manage", "all");
        // As EnsureNotAnAdminAsync: only a site admin locks, unlocks or resets the factors of another site admin.
        bool anotherAdmin = !admin && await HttpContext.RequestServices.GetRequiredService<AbilityFactory>().HoldsAdminRightsAsync(account.Id, cancellationToken);
        bool merge = features.Merges && ability.Can("merge", account) && (admin || !await HoldsRightsOfItsOwnAsync(account.Id, cancellationToken));
        bool self = account.Id == CurrentAccountId;
        bool settled = account.MergedIntoId is null && account.ErasedAt is null;
        (bool keptByGuard, bool onlyGuards) = await KeptByGuardAsync(account, cancellationToken);
        return new AccountCanDto(
            Update: ability.Can("update", account),
            Lock: !anotherAdmin && ability.Can("lock", account),
            Unlock: !anotherAdmin && ability.Can("unlock", account),
            Merge: merge,
            ResetSecondFactor: features.TwoFactor && !anotherAdmin && ability.Can("reset-second-factor", account),
            Erase: admin && features.Erasure,
            ExportData: admin && features.DataExport)
        {
            Deactivate = settled && !self && !account.IsAgent && !anotherAdmin && ability.Can("deactivate", account),
            Activate = settled && !account.IsAgent && !anotherAdmin && ability.Can("activate", account),
            ResetPassword = settled && !account.IsService && !anotherAdmin && keptByGuard && (account.MailTo ?? account.Email) is { Length: > 0 }
                && ability.Can("reset-password", account),
            Delete = settled && !self && !account.IsService && account.LastLoginAt is null && onlyGuards && ability.Can("delete", account),
        };
    }

    /// <summary>
    /// Whether Guard keeps the account's winning record (an internal directory's, so a password is Guard's to set), and
    /// whether every record with its username is Guard's (no directory would bring it back after a delete).
    /// </summary>
    private Task<(bool KeptByGuard, bool OnlyGuards)> KeptByGuardAsync(Account account, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db =>
        {
            var records = await db.DirectoryUsers.AsNoTracking()
                .Where(u => u.NormalizedUsername == account.NormalizedUsername)
                .Join(db.Directories, u => u.DirectoryId, d => d.Id, (u, d) => new { u.Id, u.IsActive, Internal = d.Type == GuardConstants.InternalType })
                .ToListAsync(cancellationToken);
            bool kept = records.Any(r => r.Id == account.DirectoryUserId && r.Internal && r.IsActive);
            return (kept, records.All(r => r.Internal));
        }, cancellationToken: cancellationToken);

    /// <summary>Whether the account has roles or groups of its own (granted to it, not from a directory): only an admin merges it.</summary>
    private Task<bool> HoldsRightsOfItsOwnAsync(Guid accountId, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db =>
            await db.RoleGrants.AnyAsync(g => g.PrincipalType == PrincipalType.Account && g.PrincipalId == accountId, cancellationToken)
            || await db.Memberships.AnyAsync(m => m.MemberType == MemberType.Account && m.MemberId == accountId && m.Source == MembershipSource.Manual, cancellationToken),
            cancellationToken: cancellationToken);

    /// <summary>A user to create in an internal directory: Guard's own, or another such as Customers.</summary>
    public sealed record CreateAccountInput(string Username, string DisplayName, string? Email, string Password, Guid? DirectoryId = null);

    /// <summary>Creates a user in an internal directory (Guard's own by default).</summary>
    [HttpPost]
    [StepUp(StepUpCategories.Accounts)]
    public async Task<AccountDto> Create([FromBody] CreateAccountInput input, CancellationToken cancellationToken)
    {
        Ensure(await AbilityAsync(cancellationToken), "create", "Account");
        if (string.IsNullOrWhiteSpace(input.Username) || !Usernames.Pattern().IsMatch(input.Username.Trim()))
        {
            throw new UserFriendlyException(Usernames.Rule);
        }

        Usernames.EnsureNotReserved(input.Username, input.DisplayName);
        if (options.Value.Passwords.Problem(input.Password) is { } problem)
        {
            throw new UserFriendlyException(problem);
        }

        string normalized = GuardConstants.Normalize(input.Username);
        Guid directoryId = input.DirectoryId ?? GuardConstants.InternalDirectoryId;
        (AccountDto dto, List<object> events) = await guardDb.RunAsync(async db =>
        {
            UserDirectory directory = await db.Directories.FirstOrDefaultAsync(d => d.Id == directoryId, cancellationToken)
                ?? throw new UserFriendlyException("There's no such directory.");
            if (!directory.IsInternal)
            {
                throw new UserFriendlyException($"{directory.Name} keeps its own users: create them there.");
            }

            if (await db.DirectoryUsers.AnyAsync(u => u.DirectoryId == directoryId && u.NormalizedUsername == normalized, cancellationToken))
            {
                throw new UserFriendlyException($"{directory.Name} already has a user called '{input.Username}'.");
            }

            DirectoryUser user = new(Guid.NewGuid(), directoryId, $"internal:{normalized}", input.Username)
            {
                DisplayName = string.IsNullOrWhiteSpace(input.DisplayName) ? input.Username : DisplayNames.Check(input.DisplayName.Trim()),
                Email = input.Email?.Trim(),
            };
            user.PasswordHash = AuthService.HashPassword(user, input.Password);
            db.DirectoryUsers.Add(user);
            await db.SaveChangesAsync(cancellationToken);

            List<object> events = await projector.RebuildAsync(db, [normalized], cancellationToken);
            await db.SaveChangesAsync(cancellationToken);

            await Organizations.ApplyDomainsAsync(db, cancellationToken);
            Account account = await db.Accounts.FirstAsync(a => a.NormalizedUsername == normalized, cancellationToken);
            string directoryName = await db.Directories.Where(d => d.Id == account.DirectoryId).Select(d => d.Name).FirstAsync(cancellationToken);
            audit.Add(db, SecurityAuditTypes.AccountCreated, Target(account), new { directory = directoryName });
            await db.SaveChangesAsync(cancellationToken);
            return (AccountDto.From(account, directoryName), events);
        }, requiresNew: true, cancellationToken, isTransactional: true);

        await PublishAsync(events);
        await merges.FoldPlaceholdersAsync(MergeReasons.AccountCreated, cancellationToken); // a placeholder with this address joins them
        return dto;
    }

    [HttpPost("{id:guid}/lock")]
    [StepUp(StepUpCategories.Accounts)]
    public Task<AccountDto> Lock(Guid id, CancellationToken cancellationToken) => SetLockedAsync(id, locked: true, cancellationToken);

    [HttpPost("{id:guid}/unlock")]
    [StepUp(StepUpCategories.Accounts)]
    public Task<AccountDto> Unlock(Guid id, CancellationToken cancellationToken) => SetLockedAsync(id, locked: false, cancellationToken);

    /// <summary>
    /// Deactivates an account: the person left. Inactive whatever its directory says, until activated again; its sessions
    /// end, and its tokens stop working with it. A lock is for a hold on someone still here.
    /// </summary>
    [HttpPost("{id:guid}/deactivate")]
    [StepUp(StepUpCategories.Accounts)]
    public Task<AccountDto> Deactivate(Guid id, CancellationToken cancellationToken) => SetDeactivatedAsync(id, deactivated: true, cancellationToken);

    /// <summary>Activates a deactivated account again: it's Active once its directory says so too.</summary>
    [HttpPost("{id:guid}/activate")]
    [StepUp(StepUpCategories.Accounts)]
    public Task<AccountDto> Activate(Guid id, CancellationToken cancellationToken) => SetDeactivatedAsync(id, deactivated: false, cancellationToken);

    /// <summary>A person's second factors as an admin sees them: what their groups ask, what they set up, the recovery codes left.</summary>
    [HttpGet("{id:guid}/second-factors")]
    [GuardFeature(nameof(GuardFeatures.TwoFactor))]
    public async Task<Services.TwoFactor.MySecondFactorsDto> SecondFactors(Guid id, [FromServices] Services.TwoFactor.SecondFactors secondFactors,
        CancellationToken cancellationToken)
    {
        Ensure(await AbilityAsync(cancellationToken), "read", await AccountAsync(id, cancellationToken));
        return await secondFactors.ListAsync(id, cancellationToken);
    }

    /// <summary>
    /// Resets a person's second factors, for someone who lost their phone and their recovery codes: every one
    /// goes, and a group that requires one has them set it up again at their next sign-in.
    /// </summary>
    [HttpDelete("{id:guid}/second-factors")]
    [GuardFeature(nameof(GuardFeatures.TwoFactor))]
    [StepUp(StepUpCategories.Security)]
    public async Task<NoContentResult> ResetSecondFactors(Guid id, [FromServices] Services.TwoFactor.SecondFactors secondFactors, CancellationToken cancellationToken)
    {
        if (id == CurrentAccountId)
        {
            throw new UserFriendlyException("You can't reset your own second factors. Remove them from your profile, or ask another admin.");
        }

        Casl.Ability ability = await AbilityAsync(cancellationToken);
        Ensure(ability, "reset-second-factor", await AccountAsync(id, cancellationToken));
        await EnsureNotAnAdminAsync(ability, id, "reset the second factors of", cancellationToken);
        await secondFactors.ResetAsync(id, cancellationToken);
        return NoContent();
    }

    /// <summary>
    /// Removes one of a person's second factors, for a lost device: one of their passkeys, or the app. Not their last while
    /// a group of theirs or the site admins' rule asks for one (<c>last_strong_factor</c>): the reset does that. They're told.
    /// </summary>
    [HttpDelete("{id:guid}/second-factors/{factorId:guid}")]
    [GuardFeature(nameof(GuardFeatures.TwoFactor))]
    [StepUp(StepUpCategories.Security)]
    public async Task<NoContentResult> RemoveSecondFactor(Guid id, Guid factorId, [FromServices] Services.TwoFactor.SecondFactors secondFactors,
        CancellationToken cancellationToken)
    {
        if (id == CurrentAccountId)
        {
            throw new UserFriendlyException("Remove your own second factors from your profile.");
        }

        Casl.Ability ability = await AbilityAsync(cancellationToken);
        Ensure(ability, "reset-second-factor", await AccountAsync(id, cancellationToken));
        await EnsureNotAnAdminAsync(ability, id, "remove a second factor of", cancellationToken);
        await secondFactors.RemoveAsync(id, factorId, cancellationToken, byAdmin: true);
        return NoContent();
    }

    private async Task<AccountDto> SetLockedAsync(Guid id, bool locked, CancellationToken cancellationToken)
    {
        if (locked && id == CurrentAccountId)
        {
            throw new UserFriendlyException("You can't lock your own account.");
        }

        Casl.Ability ability = await AbilityAsync(cancellationToken);
        await EnsureNotAnAdminAsync(ability, id, locked ? "lock" : "unlock", cancellationToken);
        (AccountDto dto, List<object> events) = await guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.FirstOrDefaultAsync(a => a.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Account), id);
            Ensure(ability, locked ? "lock" : "unlock", account);
            if (account.LockedLocally != locked)
            {
                audit.Add(db, locked ? SecurityAuditTypes.AccountLocked : SecurityAuditTypes.AccountUnlocked, Target(account));
            }

            account.LockedLocally = locked;
            await db.SaveChangesAsync(cancellationToken);
            List<object> events = await projector.RebuildAsync(db, [account.NormalizedUsername], cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            string directoryName = await db.Directories.Where(d => d.Id == account.DirectoryId).Select(d => d.Name).FirstAsync(cancellationToken);
            return (AccountDto.From(account, directoryName), events);
        }, requiresNew: true, cancellationToken, isTransactional: true);

        // Unlocking later doesn't bring back a session someone else may have had: browsers', the phone's, scripts'.
        if (locked)
        {
            await sessions.EndEverywhereAsync(id, keepSession: null, keepAuthorization: null, "locked", cancellationToken);
        }

        await PublishAsync(events);
        return dto;
    }

    // ---- Passwords, invitations, deleting an unused account (0.9.0) ----

    /// <summary>
    /// Mails the person a link to choose a new password, for an account whose directory Guard keeps. The current one keeps
    /// working until they do; the link works Guard:Passwords:AdminResetHours (24 by default).
    /// </summary>
    [HttpPost("{id:guid}/password-reset")]
    [StepUp(StepUpCategories.Accounts)]
    public async Task<NoContentResult> ResetPassword(Guid id, CancellationToken cancellationToken)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
        Account account = await AccountAsync(id, cancellationToken);
        Ensure(ability, "reset-password", account);
        await EnsureNotAnAdminAsync(ability, id, "reset the password of", cancellationToken);
        EnsurePerson(account);
        await self.SendPasswordLinkAsync(id, invitation: false, inviter: null, cancellationToken);
        await AuditAsync(SecurityAuditTypes.PasswordResetSent, account, null, cancellationToken);
        return NoContent();
    }

    /// <summary>People to invite: an address each, and their name if it's known; the directory they join (an internal one).</summary>
    public sealed record InvitationInput(List<InvitePersonInput> People, Guid? DirectoryId = null);

    public sealed record InvitePersonInput(string Email, string? DisplayName = null);

    /// <summary>Who was invited, and the addresses refused (with why): one refused doesn't stop the others.</summary>
    public sealed record InvitationResultDto(List<AccountDto> Invited, List<InvitationRefusedDto> Refused);

    public sealed record InvitationRefusedDto(string Email, string Reason);

    /// <summary>
    /// Invites people, at most 50 a call: each gets an account in an internal directory (Guard's own by default) with no
    /// password, its username from the address (made unique), and a mailed link to choose a password that works
    /// Guard:Passwords:InvitationDays (7 by default). The account shows as invited until they first sign in.
    /// </summary>
    [HttpPost("invitations")]
    [StepUp(StepUpCategories.Accounts)]
    public async Task<InvitationResultDto> Invite([FromBody] InvitationInput input, CancellationToken cancellationToken)
    {
        Ensure(await AbilityAsync(cancellationToken), "create", "Account");
        if (input.People is not { Count: > 0 and <= 50 })
        {
            throw new UserFriendlyException("Invite 1 to 50 people at a time.");
        }

        Guid directoryId = input.DirectoryId ?? GuardConstants.InternalDirectoryId;
        string inviter = await InviterAsync(cancellationToken);
        List<AccountDto> invited = [];
        List<InvitationRefusedDto> refused = [];
        HashSet<string> seen = [];
        foreach (InvitePersonInput person in input.People)
        {
            string email = (person.Email ?? "").Trim();
            string normalized = GuardConstants.Normalize(email);
            if (!LooksLikeAnAddress(email))
            {
                refused.Add(new(email, "This isn't an email address."));
                continue;
            }

            if (!seen.Add(normalized))
            {
                refused.Add(new(email, "This address is listed twice."));
                continue;
            }

            (AccountDto? dto, string? why, List<object> events) = await guardDb.RunAsync(async db =>
            {
                UserDirectory directory = await db.Directories.FirstOrDefaultAsync(d => d.Id == directoryId, cancellationToken)
                    ?? throw new UserFriendlyException("There's no such directory.");
                if (!directory.IsInternal || !directory.IsActive)
                {
                    throw new UserFriendlyException($"{directory.Name} keeps its own users: invite people to an internal directory.");
                }

                if (await Addresses.ActiveWithAddress(db, normalized).AnyAsync(cancellationToken))
                {
                    return ((AccountDto?)null, "Someone already has an account with this address.", new List<object>());
                }

                string local = email[..email.IndexOf('@')];
                string username = await FreeUsernameAsync(db, local, cancellationToken);
                string name = string.IsNullOrWhiteSpace(person.DisplayName) ? local : DisplayNames.Check(person.DisplayName.Trim());
                Usernames.EnsureNotReserved(username, name);
                string key = GuardConstants.Normalize(username);
                db.DirectoryUsers.Add(new DirectoryUser(Guid.NewGuid(), directoryId, $"internal:{key}", username) { DisplayName = name, Email = email });
                await db.SaveChangesAsync(cancellationToken);
                List<object> events = await projector.RebuildAsync(db, [key], cancellationToken);
                await db.SaveChangesAsync(cancellationToken);
                Account account = await db.Accounts.FirstAsync(a => a.NormalizedUsername == key, cancellationToken);
                (account.InvitedAt, account.InvitedBy) = (DateTime.UtcNow, CurrentAccountId);
                await db.SaveChangesAsync(cancellationToken);
                await Organizations.ApplyDomainsAsync(db, cancellationToken);
                audit.Add(db, SecurityAuditTypes.AccountInvited, Target(account), new { directory = directory.Name });
                await db.SaveChangesAsync(cancellationToken);
                return (AccountDto.From(account, directory.Name), (string?)null, events);
            }, requiresNew: true, cancellationToken, isTransactional: true);

            if (dto is null)
            {
                refused.Add(new(email, why!));
                continue;
            }

            await PublishAsync(events);
            await self.SendPasswordLinkAsync(dto.Id, invitation: true, inviter, cancellationToken);
            invited.Add(dto);
        }

        return new InvitationResultDto(invited, refused);
    }

    /// <summary>Sends an invitation again, with a new link: for an account invited and not signed in yet.</summary>
    [HttpPost("{id:guid}/invitation")]
    [StepUp(StepUpCategories.Accounts)]
    public async Task<NoContentResult> Reinvite(Guid id, CancellationToken cancellationToken)
    {
        Ensure(await AbilityAsync(cancellationToken), "create", "Account");
        Account account = await AccountAsync(id, cancellationToken);
        if (account.InvitedAt is null || account.LastLoginAt is not null)
        {
            throw new UserFriendlyException("This account isn't waiting on an invitation.", GuardErrorCodes.Conflict);
        }

        await self.SendPasswordLinkAsync(id, invitation: true, await InviterAsync(cancellationToken), cancellationToken);
        await AuditAsync(SecurityAuditTypes.AccountInvited, account, new { again = true }, cancellationToken);
        return NoContent();
    }

    /// <summary>
    /// Deletes an account nobody has used yet: never signed in, kept by no directory but Guard's own, no service account,
    /// in no merge, and held by nothing in the host or its plugins (what a merge would move, and any usage counter). Its
    /// groups, roles, addresses and factors go with it; the security log keeps that it was deleted. Anything else is
    /// refused: history that names an account would read as an unknown person, so a used one is deactivated instead.
    /// This is also how an invitation is cancelled.
    /// </summary>
    [HttpDelete("{id:guid}")]
    [StepUp(StepUpCategories.Accounts)]
    public async Task<NoContentResult> Delete(Guid id, CancellationToken cancellationToken)
    {
        if (id == CurrentAccountId)
        {
            throw new UserFriendlyException("You can't delete your own account.");
        }

        Casl.Ability ability = await AbilityAsync(cancellationToken);
        Account account = await AccountAsync(id, cancellationToken);
        Ensure(ability, "delete", account);
        await EnsureNotAnAdminAsync(ability, id, "delete", cancellationToken);
        EnsurePerson(account);
        if (account.MergedIntoId is not null || account.ErasedAt is not null)
        {
            throw new UserFriendlyException("This account was merged or erased: it stays as it is.", GuardErrorCodes.Conflict);
        }

        if (account.LastLoginAt is not null)
        {
            throw new UserFriendlyException("This account has signed in, so it has a history: deactivate it instead.", GuardErrorCodes.AccountSignedIn);
        }

        if (!(await KeptByGuardAsync(account, cancellationToken)).OnlyGuards)
        {
            throw new UserFriendlyException("A directory keeps this account, so it would come back on the next sync: deactivate it there.", GuardErrorCodes.AccountSynced);
        }

        List<MergePartDto> held = await merges.UsageAsync(id, cancellationToken);
        if (held.Count > 0 || await guardDb.RunAsync(db => db.Merges.AnyAsync(m => m.SourceId == id || m.SurvivorId == id, cancellationToken), cancellationToken: cancellationToken))
        {
            throw InUse(held);
        }

        try
        {
            await guardDb.RunAsync(async db =>
            {
                List<Guid> records = await db.DirectoryUsers.Where(u => u.NormalizedUsername == account.NormalizedUsername).Select(u => u.Id).ToListAsync(cancellationToken);
                await db.Memberships.Where(m => (m.MemberType == MemberType.Account && m.MemberId == id)
                    || (m.MemberType == MemberType.DirectoryUser && records.Contains(m.MemberId))).ExecuteDeleteAsync(cancellationToken);
                await db.RoleGrants.Where(g => g.PrincipalType == PrincipalType.Account && g.PrincipalId == id).ExecuteDeleteAsync(cancellationToken);
                await db.PersonalAccessTokens.Where(t => t.AccountId == id).ExecuteDeleteAsync(cancellationToken);
                await db.SecondFactors.Where(f => f.AccountId == id).ExecuteDeleteAsync(cancellationToken);
                await db.Passkeys.Where(p => p.AccountId == id).ExecuteDeleteAsync(cancellationToken);
                await db.PasskeyChallenges.Where(c => c.AccountId == id).ExecuteDeleteAsync(cancellationToken);
                await db.RecoveryCodes.Where(c => c.AccountId == id).ExecuteDeleteAsync(cancellationToken);
                await db.SentCodes.Where(c => c.AccountId == id).ExecuteDeleteAsync(cancellationToken);
                await db.SignInTickets.Where(t => t.AccountId == id).ExecuteDeleteAsync(cancellationToken);
                await db.SessionHandoffs.Where(h => h.AccountId == id).ExecuteDeleteAsync(cancellationToken);
                await db.WebSessions.Where(s => s.AccountId == id).ExecuteDeleteAsync(cancellationToken);
                await db.AccountEmails.Where(e => e.AccountId == id).ExecuteDeleteAsync(cancellationToken);
                await db.DirectoryUsers.Where(u => records.Contains(u.Id)).ExecuteDeleteAsync(cancellationToken);
                await db.Accounts.Where(a => a.Id == id).ExecuteDeleteAsync(cancellationToken);
                audit.Add(db, SecurityAuditTypes.AccountDeleted, Target(account));
                await db.SaveChangesAsync(cancellationToken);
            }, requiresNew: true, cancellationToken, isTransactional: true);
        }
        catch (Exception ex) when (IsForeignKey(ex))
        {
            // The host's database still names the account somewhere nothing counted: kept, as if a count had said so.
            throw InUse([]);
        }

        return NoContent();
    }

    private static UserFriendlyException InUse(List<MergePartDto> held)
    {
        UserFriendlyException refused = new("Something still holds this account, so its history would lose who it was: deactivate it instead.", GuardErrorCodes.AccountInUse);
        refused.Data["parts"] = held.Select(p => new { p.Key, p.Plugin, Counts = p.Counts.Select(c => new { c.Key, c.Count, c.Label }), p.Error }).ToList();
        return refused;
    }

    /// <summary>A foreign key refused the delete (Postgres 23503), however deep the provider wrapped it.</summary>
    private static bool IsForeignKey(Exception ex)
    {
        for (Exception? e = ex; e is not null; e = e.InnerException)
        {
            if (e is Npgsql.PostgresException { SqlState: "23503" })
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>A person's action, never a service account's (an agent's, managed where it was made).</summary>
    private static void EnsurePerson(Account account)
    {
        if (account.IsService)
        {
            throw new UserFriendlyException("A service account is managed where it was made, not here.", GuardErrorCodes.ServiceAccount);
        }
    }

    private async Task<string> InviterAsync(CancellationToken cancellationToken) =>
        await guardDb.RunAsync(db => db.Accounts.Where(a => a.Id == CurrentAccountId).Select(a => a.DisplayName).FirstOrDefaultAsync(cancellationToken), cancellationToken: cancellationToken)
        ?? "An administrator";

    private Task AuditAsync(string type, Account account, object? detail, CancellationToken cancellationToken) => guardDb.RunAsync(async db =>
    {
        audit.Add(db, type, Target(account), detail);
        await db.SaveChangesAsync(cancellationToken);
    }, requiresNew: true, cancellationToken, isTransactional: true);

    /// <summary>A username from an address's local part that no directory and no account has: sara, sara2, sara3…</summary>
    private static async Task<string> FreeUsernameAsync(GuardDbContext db, string local, CancellationToken cancellationToken)
    {
        string stem = new string(local.Where(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_').ToArray()).Trim('.', '-', '_');
        stem = stem.Length < 2 ? "user" : stem[..Math.Min(stem.Length, 60)];
        for (int n = 1; ; n++)
        {
            string candidate = n == 1 ? stem : $"{stem}{n}";
            string key = GuardConstants.Normalize(candidate);
            if (!Usernames.IsReserved(candidate)
                && !await db.DirectoryUsers.AnyAsync(u => u.NormalizedUsername == key, cancellationToken)
                && !await db.Accounts.AnyAsync(a => a.NormalizedUsername == key, cancellationToken))
            {
                return candidate;
            }
        }
    }

    private static bool LooksLikeAnAddress(string email) =>
        email.Length is > 2 and <= 254 && email.IndexOf('@') is > 0 and var at && at < email.Length - 1 && email.IndexOf('@', at + 1) < 0
        && !email.Any(char.IsWhiteSpace);

    private async Task<AccountDto> SetDeactivatedAsync(Guid id, bool deactivated, CancellationToken cancellationToken)
    {
        if (deactivated && id == CurrentAccountId)
        {
            throw new UserFriendlyException("You can't deactivate your own account.");
        }

        Casl.Ability ability = await AbilityAsync(cancellationToken);
        await EnsureNotAnAdminAsync(ability, id, deactivated ? "deactivate" : "activate", cancellationToken);
        (AccountDto dto, List<object> events) = await guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.FirstOrDefaultAsync(a => a.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Account), id);
            Ensure(ability, deactivated ? "deactivate" : "activate", account);
            if (account.IsAgent)
            {
                throw new UserFriendlyException("An agent is paused where it's managed, not here.", GuardErrorCodes.ServiceAccount);
            }

            if (account.MergedIntoId is not null || account.ErasedAt is not null)
            {
                throw new UserFriendlyException("This account was merged or erased: it stays as it is.", GuardErrorCodes.Conflict);
            }

            if (account.DeactivatedLocally != deactivated)
            {
                audit.Add(db, deactivated ? SecurityAuditTypes.AccountDeactivated : SecurityAuditTypes.AccountActivated, Target(account));
            }

            account.DeactivatedLocally = deactivated;
            await db.SaveChangesAsync(cancellationToken);
            List<object> events = await projector.RebuildAsync(db, [account.NormalizedUsername], cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            string directoryName = await db.Directories.Where(d => d.Id == account.DirectoryId).Select(d => d.Name).FirstAsync(cancellationToken);
            return (AccountDto.From(account, directoryName), events);
        }, requiresNew: true, cancellationToken, isTransactional: true);

        // As a lock: what was signed in ends (browsers, the phone, scripts); personal tokens and apps stop with the account.
        if (deactivated)
        {
            await sessions.EndEverywhereAsync(id, keepSession: null, keepAuthorization: null, "deactivated", cancellationToken);
        }

        await PublishAsync(events);
        return dto;
    }

    /// <summary>
    /// A right short of an admin's (a helpdesk's) doesn't reach an account with an admin's rights: locking one ends its
    /// every session, and unlocking one an admin locked would undo them.
    /// </summary>
    private async Task EnsureNotAnAdminAsync(Casl.Ability ability, Guid id, string what, CancellationToken cancellationToken)
    {
        if (!ability.Can("manage", "all") && await HttpContext.RequestServices.GetRequiredService<AbilityFactory>().HoldsAdminRightsAsync(id, cancellationToken))
        {
            throw new UserFriendlyException($"Only an administrator can {what} an administrator.", GuardErrorCodes.Forbidden);
        }
    }

    // ---- Addresses: an admin's are verified at once ----

    [HttpGet("{id:guid}/emails")]
    public async Task<AccountEmailsDto> Emails(Guid id, CancellationToken cancellationToken)
    {
        Ensure(await AbilityAsync(cancellationToken), "read", await AccountAsync(id, cancellationToken));
        return await emails.ListAsync(id, cancellationToken);
    }

    /// <summary>
    /// Adds an address, verified; a placeholder with it is merged into this account. Admins only: a verified address
    /// receives password resets and counts for email-domain organizations, so a right to update an account, or one's
    /// own, isn't enough (a person adds their own at /me/emails, through a mailed link).
    /// </summary>
    [HttpPost("{id:guid}/emails")]
    [Authorize(Policy = GuardPolicies.Admin)]
    [StepUp(StepUpCategories.Accounts)]
    public async Task<AccountEmailsDto> AddEmail(Guid id, [FromBody] AddEmailInput input, CancellationToken cancellationToken)
    {
        Account account = await AccountAsync(id, cancellationToken);
        Ensure(await AbilityAsync(cancellationToken), "update", account);
        AccountEmailsDto result = await emails.AddVerifiedAsync(id, input.Email, CurrentAccountId, cancellationToken);
        // A verified address receives password resets and matches mail and sign-ups.
        await audit.WriteAsync(SecurityAuditTypes.AddressAdded, Target(account), new { email = input.Email.Trim() }, cancellationToken);
        return result;
    }

    [HttpDelete("{id:guid}/emails/{emailId:guid}")]
    [Authorize(Policy = GuardPolicies.Admin)]
    [StepUp(StepUpCategories.Accounts)]
    public async Task<AccountEmailsDto> RemoveEmail(Guid id, Guid emailId, CancellationToken cancellationToken)
    {
        Account account = await AccountAsync(id, cancellationToken);
        Ensure(await AbilityAsync(cancellationToken), "update", account);
        string? email = (await emails.ListAsync(id, cancellationToken)).Addresses.FirstOrDefault(a => a.Id == emailId)?.Email;
        AccountEmailsDto result = await emails.RemoveAsync(id, emailId, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.AddressRemoved, Target(account), new { email }, cancellationToken);
        return result;
    }

    /// <summary>Where mail goes: one of the account's verified addresses, or null for its directory's.</summary>
    [HttpPut("{id:guid}/mail-to")]
    [Authorize(Policy = GuardPolicies.Admin)]
    [StepUp(StepUpCategories.Accounts)]
    public async Task<AccountEmailsDto> MailTo(Guid id, [FromBody] MailToInput input, CancellationToken cancellationToken)
    {
        Account account = await AccountAsync(id, cancellationToken);
        Ensure(await AbilityAsync(cancellationToken), "update", account);
        AccountEmailsDto result = await emails.SetMailToAsync(id, input.Email, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.MailToChanged, Target(account), new { email = result.MailTo }, cancellationToken);
        return result;
    }

    // ---- Merging ----

    /// <summary>Addresses more than one account has: candidates to merge.</summary>
    [HttpGet("duplicates")]
    public async Task<List<DuplicateDto>> Duplicates(CancellationToken cancellationToken)
    {
        Ensure(await AbilityAsync(cancellationToken), "merge", "Account");
        return await merges.DuplicatesAsync(cancellationToken);
    }

    /// <summary>What merging this account into another would move, without moving anything.</summary>
    [HttpPost("{id:guid}/merge/preview")]
    [GuardFeature(nameof(GuardFeatures.Merges))]
    [Reads]
    public async Task<MergePreviewDto> PreviewMerge(Guid id, [FromBody] MergeInput input, CancellationToken cancellationToken)
    {
        await EnsureMergeAsync(id, input.SurvivorId, cancellationToken);
        return await merges.PreviewAsync(id, input.SurvivorId, CurrentAccountId, cancellationToken);
    }

    /// <summary>
    /// Merges this account into another: everything it did, owns or is named in moves there, and it stays inactive. An
    /// account that can sign in needs Confirm to be its username.
    /// </summary>
    [HttpPost("{id:guid}/merge")]
    [GuardFeature(nameof(GuardFeatures.Merges))]
    [StepUp(StepUpCategories.Roles)]
    public async Task<AccountMergeDto> Merge(Guid id, [FromBody] MergeInput input, CancellationToken cancellationToken)
    {
        await EnsureMergeAsync(id, input.SurvivorId, cancellationToken);
        return await merges.MergeAsync(id, input.SurvivorId, CurrentAccountId, MergeReasons.Admin, input.Confirm, cancellationToken);
    }

    /// <summary>
    /// A merge moves the source's grants and the memberships added in Guard to the survivor, so a merge right short of an
    /// admin's can't make oneself the survivor, nor merge an account that holds either: that would hand over rights the
    /// merger may not give.
    /// </summary>
    private async Task EnsureMergeAsync(Guid sourceId, Guid survivorId, CancellationToken cancellationToken)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
        Ensure(ability, "merge", await AccountAsync(sourceId, cancellationToken));
        Ensure(ability, "merge", await AccountAsync(survivorId, cancellationToken));
        if (ability.Can("manage", "all"))
        {
            return;
        }

        if (survivorId == CurrentAccountId)
        {
            throw new UserFriendlyException("Only an administrator can merge another account into their own.", GuardErrorCodes.Forbidden);
        }

        if (await HoldsRightsOfItsOwnAsync(sourceId, cancellationToken))
        {
            throw new UserFriendlyException("This account has roles or groups of its own: only an administrator can merge it.", GuardErrorCodes.Forbidden);
        }
    }

    /// <summary>Corrects an internal account's display name; a directory's account is corrected in its directory.</summary>
    [HttpPut("{id:guid}/name")]
    [StepUp(StepUpCategories.Accounts)]
    public async Task<AccountNameDto> Rename(Guid id, [FromBody] AccountNameInput input, [FromServices] AccountCorrections corrections, CancellationToken cancellationToken)
    {
        Account account = await AccountAsync(id, cancellationToken);
        Ensure(await AbilityAsync(cancellationToken), "update", account);
        AccountChangedEto changed = await corrections.RenameAsync(id, input.DisplayName, input.DisplayNames, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.AccountRenamed, Target(account), new { before = changed.OldDisplayName, after = changed.NewDisplayName, names = input.DisplayNames }, cancellationToken);
        await PublishAsync([changed]);
        return new AccountNameDto(changed.NewDisplayName!) { DisplayNames = (await AccountAsync(id, cancellationToken)).DisplayNames };
    }

    /// <summary>One of an internal account's confirmed addresses becomes its primary; the one before is told.</summary>
    [HttpPost("{id:guid}/emails/{emailId:guid}/primary")]
    [StepUp(StepUpCategories.Accounts)]
    public async Task<AccountEmailsDto> SetPrimary(Guid id, Guid emailId, [FromServices] AccountCorrections corrections, CancellationToken cancellationToken)
    {
        Account account = await AccountAsync(id, cancellationToken);
        Ensure(await AbilityAsync(cancellationToken), "update", account);
        AccountChangedEto changed = await corrections.SetPrimaryAsync(id, emailId, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.PrimaryAddressChanged, Target(account), new { before = changed.OldEmail, after = changed.NewEmail }, cancellationToken);
        await PublishAsync([changed]);
        return await emails.ListAsync(id, cancellationToken);
    }

    private static AuditTarget Target(Account account) => new("Account", account.Id, account.Username);

    private Task<Account> AccountAsync(Guid id, CancellationToken cancellationToken) => guardDb.RunAsync(async db =>
        await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id, cancellationToken) ?? throw new EntityNotFoundException(typeof(Account), id),
        cancellationToken: cancellationToken);
}

/// <summary>Merges as recorded: every one, or an account's; and resuming one a plugin didn't finish.</summary>
[Route("api/guard/merges")]
[Authorize]
[GuardFeature(nameof(GuardFeatures.Merges))]
public class MergesController(AccountMergeService merges, GuardDb guardDb) : GuardControllerBase
{
    /// <summary>The merges the caller may see: an admin's are all; a narrower merge right's, those of accounts it may merge.</summary>
    [HttpGet]
    public async Task<List<AccountMergeDto>> List([FromQuery] Guid? accountId, [FromQuery] int take = 100, CancellationToken cancellationToken = default)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
        Ensure(ability, "merge", "Account");
        return await merges.ListAsync(accountId, take, cancellationToken, ability.Can("manage", "all") ? null : ability);
    }

    [HttpGet("{id:guid}")]
    public async Task<AccountMergeDto> Get(Guid id, CancellationToken cancellationToken)
    {
        AccountMergeDto merge = await merges.GetAsync(id, cancellationToken);
        await EnsureBothAsync(merge, cancellationToken);
        return merge;
    }

    /// <summary>Asks the plugins that haven't finished the merge (they failed, or were off) to move their rows now.</summary>
    [HttpPost("{id:guid}/resume")]
    [StepUp(StepUpCategories.Roles)]
    public async Task<AccountMergeDto> Resume(Guid id, CancellationToken cancellationToken)
    {
        await EnsureBothAsync(await merges.GetAsync(id, cancellationToken), cancellationToken);
        return await merges.ResumeAsync(id, cancellationToken);
    }

    /// <summary>403 unless the caller may merge both of the merge's accounts, as it took to start it.</summary>
    private async Task EnsureBothAsync(AccountMergeDto merge, CancellationToken cancellationToken)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
        List<Account> accounts = await guardDb.RunAsync(db => db.Accounts.AsNoTracking().Where(a => a.Id == merge.SourceId || a.Id == merge.SurvivorId).ToListAsync(cancellationToken),
            cancellationToken: cancellationToken);
        Ensure(ability, "merge", "Account");
        foreach (Account account in accounts)
        {
            Ensure(ability, "merge", account);
        }
    }
}

public sealed record AccountNameDto(string DisplayName)
{
    /// <summary>The person's name in other languages, as saved.</summary>
    public Dictionary<string, string> DisplayNames { get; init; } = [];
}

/// <summary>
/// A person corrects their own account (PDPL's right to correction): their display name, and which of
/// their confirmed addresses is their primary. Only an account of the internal directory; each asks for the password
/// again, is limited as self-service is, and goes in the security log. Sign-in keeps taking the username.
/// </summary>
[Route("api/guard")]
[Authorize]
public class MyAccountController(AccountCorrections corrections, AccountEmailService emails, SecurityLog audit, SelfServiceLimiter limiter) : GuardControllerBase
{
    [HttpPut("me/name")]
    [StepUp(StepUpCategories.Profile)]
    public async Task<AccountNameDto> Rename([FromBody] AccountNameInput input, CancellationToken cancellationToken)
    {
        await LimitAsync(cancellationToken);
        AccountChangedEto changed = await corrections.RenameAsync(CurrentAccountId, input.DisplayName, input.DisplayNames, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.AccountRenamed, new AuditTarget("Account", changed.AccountId, changed.Username),
            new { before = changed.OldDisplayName, after = changed.NewDisplayName, names = input.DisplayNames }, cancellationToken);
        await PublishAsync([changed]);
        return new AccountNameDto(changed.NewDisplayName!) { DisplayNames = input.DisplayNames ?? [] };
    }

    [HttpPost("me/emails/{emailId:guid}/primary")]
    [StepUp(StepUpCategories.Profile)]
    public async Task<AccountEmailsDto> SetPrimary(Guid emailId, CancellationToken cancellationToken)
    {
        await LimitAsync(cancellationToken);
        AccountChangedEto changed = await corrections.SetPrimaryAsync(CurrentAccountId, emailId, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.PrimaryAddressChanged, new AuditTarget("Account", changed.AccountId, changed.Username),
            new { before = changed.OldEmail, after = changed.NewEmail }, cancellationToken);
        await PublishAsync([changed]);
        return await emails.ListAsync(CurrentAccountId, cancellationToken);
    }

    private async Task LimitAsync(CancellationToken cancellationToken)
    {
        if (!await limiter.AllowAsync("correction", ClientIp, null, cancellationToken))
        {
            throw new UserFriendlyException("Too many tries. Wait a while and try again.", GuardErrorCodes.TooManyRequests);
        }
    }
}

/// <summary>
/// A person's own addresses: added with a link mailed to the address, removed, and the one mail goes to.
/// Confirming takes only the link, signed in or not.
/// </summary>
[Route("api/guard")]
public class MyEmailsController(AccountEmailService emails, SelfServiceLimiter limiter) : GuardControllerBase
{
    [HttpGet("me/emails")]
    [Authorize]
    public Task<AccountEmailsDto> List(CancellationToken cancellationToken) => emails.ListAsync(CurrentAccountId, cancellationToken);

    /// <summary>Adds an address and mails a link to it; it counts once the link is followed.</summary>
    [HttpPost("me/emails")]
    [StepUp(StepUpCategories.Profile)]
    [Authorize]
    public async Task<AccountEmailsDto> Add([FromBody] AddEmailInput input, CancellationToken cancellationToken)
    {
        await LimitAsync("email-add", input.Email, cancellationToken);
        return await emails.AddForSelfAsync(CurrentAccountId, input.Email, cancellationToken);
    }

    [HttpDelete("me/emails/{emailId:guid}")]
    [Authorize]
    public Task<AccountEmailsDto> Remove(Guid emailId, CancellationToken cancellationToken) => emails.RemoveAsync(CurrentAccountId, emailId, cancellationToken);

    [HttpPut("me/mail-to")]
    [StepUp(StepUpCategories.Profile)]
    [Authorize]
    public Task<AccountEmailsDto> MailTo([FromBody] MailToInput input, CancellationToken cancellationToken) =>
        emails.SetMailToAsync(CurrentAccountId, input.Email, cancellationToken);

    /// <summary>Confirms an address from the link mailed to it.</summary>
    [AllowAnonymous]
    [HttpPost("emails/verify")]
    public async Task<object> Verify([FromBody] TokenInput input, CancellationToken cancellationToken)
    {
        await LimitAsync("email-verify", null, cancellationToken);
        (string email, string username) = await emails.VerifyAsync(input.Token, cancellationToken);
        return new { email, username };
    }

    private async Task LimitAsync(string action, string? email, CancellationToken cancellationToken)
    {
        if (!await limiter.AllowAsync(action, HttpContext.Connection.RemoteIpAddress?.ToString(), email, cancellationToken))
        {
            throw new UserFriendlyException("Too many tries. Wait a while and try again.", GuardErrorCodes.TooManyRequests);
        }
    }
}
