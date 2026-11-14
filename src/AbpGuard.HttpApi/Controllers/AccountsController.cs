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
    SecurityLog audit, AccountSessions sessions)
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
    /// A page of the accounts the caller may read, in ABP's shape: <c>totalCount</c> and <c>items</c>, the list's search
    /// and status, sorted by username, displayName, email, status, createdAt or lastLoginAt (username unless asked).
    /// </summary>
    [HttpGet("page")]
    public async Task<PagedResultDto<AccountDto>> Page([FromQuery] AccountPageInput input, CancellationToken cancellationToken)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
        Ensure(ability, "read", "Account");
        return await guardDb.RunAsync(async db =>
        {
            IQueryable<Account> query = Filtered(db, ability, input.Filter, input.Status);
            int total = await query.CountAsync(cancellationToken);
            List<Account> page = await GuardPaging.Sort(query, input.Sorting, AccountSorts, "username", a => a.Id)
                .Skip(input.SkipCount).Take(input.MaxResultCount).ToListAsync(cancellationToken);
            Dictionary<Guid, string> directories = await db.Directories.ToDictionaryAsync(d => d.Id, d => d.Name, cancellationToken);
            return new PagedResultDto<AccountDto>(total, page.Select(a => AccountDto.From(a, directories.GetValueOrDefault(a.DirectoryId, "?"))).ToList());
        }, cancellationToken: cancellationToken);
    }

    private static readonly Dictionary<string, System.Linq.Expressions.LambdaExpression> AccountSorts = new(StringComparer.OrdinalIgnoreCase)
    {
        ["username"] = GuardPaging.By<Account, string>(a => a.Username),
        ["displayName"] = GuardPaging.By<Account, string>(a => a.DisplayName),
        ["email"] = GuardPaging.By<Account, string?>(a => a.Email),
        ["status"] = GuardPaging.By<Account, AccountStatus>(a => a.Status),
        ["createdAt"] = GuardPaging.By<Account, DateTime>(a => a.CreatedAt),
        ["lastLoginAt"] = GuardPaging.By<Account, DateTime?>(a => a.LastLoginAt),
    };

    /// <summary>The accounts the ability may read (filtered in SQL), with the list's search and status.</summary>
    private static IQueryable<Account> Filtered(GuardDbContext db, Casl.Ability ability, string? search, string? status)
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

        return query;
    }

    [HttpGet("{id:guid}")]
    public async Task<AccountDetailDto> Get(Guid id, CancellationToken cancellationToken)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
        List<AccountMergeDto> merged = await merges.ListAsync(id, 50, cancellationToken);
        return await guardDb.RunAsync(async db =>
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
            return new AccountDetailDto(AccountDto.From(account, directories[account.DirectoryId].Name), identities, groups,
                await AccountEmailService.LoadAsync(db, id, cancellationToken), merged, into);
        }, cancellationToken: cancellationToken);
    }

    /// <summary>A user to create in an internal directory: Guard's own, or another such as Customers.</summary>
    public sealed record CreateAccountInput(string Username, string DisplayName, string? Email, string Password, Guid? DirectoryId = null);

    /// <summary>Creates a user in an internal directory (Guard's own by default).</summary>
    [HttpPost]
    [StepUp]
    public async Task<AccountDto> Create([FromBody] CreateAccountInput input, CancellationToken cancellationToken)
    {
        Ensure(await AbilityAsync(cancellationToken), "create", "Account");
        if (string.IsNullOrWhiteSpace(input.Username) || !Usernames.Pattern().IsMatch(input.Username.Trim()))
        {
            throw new UserFriendlyException(Usernames.Rule);
        }

        Usernames.EnsureNotReserved(input.Username, input.DisplayName);
        if (string.IsNullOrEmpty(input.Password) || input.Password.Length < 10)
        {
            throw new UserFriendlyException("Passwords need at least 10 characters.");
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
    [StepUp]
    public Task<AccountDto> Lock(Guid id, CancellationToken cancellationToken) => SetLockedAsync(id, locked: true, cancellationToken);

    [HttpPost("{id:guid}/unlock")]
    [StepUp]
    public Task<AccountDto> Unlock(Guid id, CancellationToken cancellationToken) => SetLockedAsync(id, locked: false, cancellationToken);

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
    [StepUp]
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
    [StepUp]
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
    [StepUp]
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
    [StepUp]
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
    [StepUp]
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

        bool holdsRights = await guardDb.RunAsync(async db =>
            await db.RoleGrants.AnyAsync(g => g.PrincipalType == PrincipalType.Account && g.PrincipalId == sourceId, cancellationToken)
            || await db.Memberships.AnyAsync(m => m.MemberType == MemberType.Account && m.MemberId == sourceId && m.Source == MembershipSource.Manual, cancellationToken),
            cancellationToken: cancellationToken);
        if (holdsRights)
        {
            throw new UserFriendlyException("This account has roles or groups of its own: only an administrator can merge it.", GuardErrorCodes.Forbidden);
        }
    }

    /// <summary>Corrects an internal account's display name; a directory's account is corrected in its directory.</summary>
    [HttpPut("{id:guid}/name")]
    [StepUp]
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
    [StepUp]
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
    [StepUp]
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
    [StepUp]
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
    [StepUp]
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
    [StepUp]
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
    [StepUp]
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
