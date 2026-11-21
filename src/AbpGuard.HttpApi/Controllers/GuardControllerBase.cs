using AbpGuard.Acting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using AbpGuard.Domain;
using AbpGuard.Services;
using Volo.Abp.AspNetCore.Mvc;
using Volo.Abp.Uow;

namespace AbpGuard.Controllers;

/// <summary>
/// Guard controllers manage their own units of work (GuardDb), so changes are committed before
/// events are published and plugin handlers always see committed data.
/// </summary>
[UnitOfWork(IsDisabled = true)]
[ApiExplorerSettings(IgnoreApi = false)] // visible in /openapi/v1.json (ABP hides non-remote-service controllers otherwise)
[GuardErrors] // a refusal answers with its JSON error whatever the client accepts (a download's fetch sends */*)
public abstract class GuardControllerBase : AbpControllerBase
{
    /// <summary>Whose rights the request uses and who is acting.</summary>
    protected ActingContext Acting => HttpContext.RequestServices.GetRequiredService<ActingContext>();

    /// <summary>The account whose rights apply: the subject of the acting context.</summary>
    protected Guid CurrentAccountId => Acting.SubjectId ?? throw new Volo.Abp.Authorization.AbpAuthorizationException("Not signed in.");

    protected string? ClientIp => HttpContext.Connection.RemoteIpAddress?.ToString();

    /// <summary>The request's ability, with whatever limits its token carries (applied by <see cref="AbilityFactory"/>).</summary>
    protected Task<Casl.Ability> AbilityAsync(CancellationToken cancellationToken = default) =>
        HttpContext.RequestServices.GetRequiredService<AbilityFactory>().ForAccountAsync(CurrentAccountId, cancellationToken);

    /// <summary>Whether someone is signed in (an anonymous portal visitor isn't).</summary>
    protected bool SignedIn => Acting.SignedIn;

    /// <summary>The caller's ability, or for a visitor who isn't signed in, what's granted to the Anonymous principal.</summary>
    protected Task<Casl.Ability> AbilityOrAnonymousAsync(CancellationToken cancellationToken = default) =>
        SignedIn ? AbilityAsync(cancellationToken) : HttpContext.RequestServices.GetRequiredService<AbilityFactory>().ForAnonymousAsync(cancellationToken);

    /// <summary>403 with the rule's reason when the ability denies the action on this object.</summary>
    protected static void Ensure(Casl.Ability ability, string action, object subject, string? field = null)
    {
        try
        {
            ability.EnsureCan(action, subject, field);
        }
        catch (Casl.ForbiddenException ex)
        {
            // UserFriendlyException keeps the reason in the 403 body; ABP answers its authorization exception with an empty Forbid.
            throw new Volo.Abp.UserFriendlyException(ex.Message, GuardErrorCodes.Forbidden);
        }
    }

    /// <summary>403 unless the user may do this to at least some instances of the subject.</summary>
    protected static void Ensure(Casl.Ability ability, string action, string subject)
    {
        if (!ability.Can(action, subject))
        {
            throw new Volo.Abp.UserFriendlyException($"You can't {action} {subject} records.", GuardErrorCodes.Forbidden);
        }
    }

    protected async Task PublishAsync(IEnumerable<object> events)
    {
        IGuardEventSink publisher = HttpContext.RequestServices.GetRequiredService<IGuardEventSink>();
        foreach (object e in events)
        {
            await GuardEvents.PublishAsync(publisher, e);
        }
    }
}

// ---- DTOs (see docs/api.md) ----

/// <summary>
/// An account; MergedIntoId is the account it was merged into, MailTo the address mail goes to when it isn't
/// Email, IsService whether it's a service account rather than a person.
/// </summary>
public sealed record AccountDto(
    Guid Id, string Username, string DisplayName, string? Email, string Status, string? StatusReason,
    Guid DirectoryId, string DirectoryName, DateTime? LastLoginAt, Guid? MergedIntoId = null, string? MailTo = null, bool IsService = false)
{
    /// <summary>An agent's account: a service account an automated actor works through, which holds no tokens.</summary>
    public bool IsAgent { get; init; }

    /// <summary>Invited by an admin and not signed in yet (0.9.0): its invitation may be sent again, or cancelled by deleting it.</summary>
    public bool Invited { get; init; }

    /// <summary>When it was made.</summary>
    public DateTime CreatedAt { get; init; }

    /// <summary>The person's name in other languages; DisplayName is the name as written.</summary>
    public Dictionary<string, string> DisplayNames { get; init; } = [];

    public static AccountDto From(Account a, string directoryName) =>
        new(a.Id, a.Username, a.DisplayName, a.Email, a.Status.ToString(), a.StatusReason, a.DirectoryId, directoryName, a.LastLoginAt, a.MergedIntoId, a.MailTo, a.IsService)
        {
            IsAgent = a.IsAgent,
            DisplayNames = a.DisplayNames,
            Invited = a.InvitedAt is not null && a.LastLoginAt is null,
            CreatedAt = a.CreatedAt,
        };
}

public sealed record IdentityDto(
    Guid DirectoryId, string DirectoryName, int DirectoryOrder, string ExternalId, string Username,
    string? DisplayName, string? Email, bool IsActive, bool IsWinning, DateTime? LastSyncedAt);

public sealed record EffectiveGroupDto(Guid GroupId, string Name, Guid DirectoryId, string DirectoryName, bool Direct, IReadOnlyList<string> Path);

/// <summary>An account with its directory records, groups, addresses and the merges it was in, newest first.</summary>
public sealed record AccountDetailDto(AccountDto Account, List<IdentityDto> Identities, List<EffectiveGroupDto> Groups, AccountEmailsDto Addresses,
    List<AccountMergeDto> Merges, string? MergedIntoUsername)
{
    /// <summary>What the caller may do to the account, so a screen shows only the buttons that would work.</summary>
    public AccountCanDto Can { get; init; } = AccountCanDto.None;
}

/// <summary>
/// What the caller may do to an account, as its actions would answer: the caller's ability against the account (a
/// helpdesk scoped to some directories, say), the rule that only a site admin locks, unlocks or resets the factors of
/// another site admin, an account's own roles or groups that only an admin merges, and the features that are on. Rights,
/// not state: a screen shows Lock or Unlock by the account's status. <see cref="Merge"/> is the account's side alone;
/// the survivor a merge picks is checked when it's sent.
/// </summary>
public sealed record AccountCanDto(bool Update, bool Lock, bool Unlock, bool Merge, bool ResetSecondFactor, bool Erase, bool ExportData)
{
    public static AccountCanDto None { get; } = new(false, false, false, false, false, false, false);

    /// <summary>Deactivate the account (the person left, a company's account ended) or activate it again (0.9.0); never an agent's, paused its own way.</summary>
    public bool Deactivate { get; init; }

    public bool Activate { get; init; }

    /// <summary>
    /// Mail the person a link to set a new password (0.9.0): an account whose directory Guard keeps, with an address to
    /// mail. Its invitation is sent again the same way.
    /// </summary>
    public bool ResetPassword { get; init; }

    /// <summary>
    /// Delete the account (0.9.0): only one nobody has used yet (never signed in, kept by no directory but Guard's own, no
    /// service account). Whether something in the host still holds it is answered when it's sent.
    /// </summary>
    public bool Delete { get; init; }
}

/// <summary>
/// A group: Kind (standard, directory, ou, organization); Computed when Guard works out its members (a directory's
/// or an OU's group); an organization's attributes and email domains; TwoFactor, whether its members are asked for a
/// second factor (off, optional, required, strong;).
/// </summary>
public sealed record GroupDto(
    Guid Id, string Name, string? Description, Guid DirectoryId, string DirectoryName,
    bool IsLocal, bool Writable, int DirectMemberCount, int MemberGroupCount, string Kind, bool Computed,
    Dictionary<string, string> Attributes, List<string> EmailDomains, string TwoFactor = TwoFactorModes.Off)
{
    /// <summary>Its name in other languages; Name is the English, or only, one.</summary>
    public Dictionary<string, string> Names { get; init; } = [];

    /// <summary>One of Guard's own groups (the admins and everyone): it can be renamed, but not deleted.</summary>
    public bool System { get; init; }
}

public sealed record GroupMemberDto(string MemberType, Guid MemberId, string Name, string? DisplayName, string DirectoryName, string Source, bool Removable);

public sealed record EffectiveMemberDto(Guid AccountId, string Username, string DisplayName, IReadOnlyList<string> Path);

public sealed record GroupDetailDto(GroupDto Group, List<GroupMemberDto> Members, List<GroupDto> Parents, List<EffectiveMemberDto> EffectiveMembers);

public sealed record DirectoryDto(
    Guid Id, string Name, string Type, string TypeDisplayName, int Order, bool IsActive, bool AuthenticationEnabled,
    Dictionary<string, string> Settings, int? SyncIntervalMinutes, DateTime? LastSyncAt, bool? LastSyncSucceeded,
    string? LastSyncMessage, int UserCount, int GroupCount, bool ConnectorAvailable, string? PluginKey,
    bool SecretsReadable = true, // false: stored secrets can't be decrypted on this server; re-enter them
    IReadOnlyList<string>? Warnings = null) // what its connector warns of in its settings
{
    /// <summary>Its name in other languages; Name is the English, or only, one.</summary>
    public Dictionary<string, string> Names { get; init; } = [];
}

public sealed record SyncRunDto(
    Guid Id, Guid DirectoryId, DateTime StartedAt, DateTime? FinishedAt, bool? Succeeded,
    int UsersAdded, int UsersUpdated, int UsersDeactivated, int GroupsSynced, int MembershipsSynced, string? Error)
{
    public static SyncRunDto From(SyncRun r) =>
        new(r.Id, r.DirectoryId, r.StartedAt, r.FinishedAt, r.Succeeded, r.UsersAdded, r.UsersUpdated, r.UsersDeactivated, r.GroupsSynced, r.MembershipsSynced, r.Error);
}
