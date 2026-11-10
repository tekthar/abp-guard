using System.Text.Json;
using AbpGuard.Data;
using AbpGuard.Domain;
using AbpGuard.Acting;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>What the security audit records, besides sign-ins (auth.*) and plugins (plugin.*).</summary>
public static class SecurityAuditTypes
{
    /// <summary>A query's results downloaded as a file.</summary>
    public const string QueryExport = "query.export";

    public const string GrantAdded = "grant.added";
    public const string GrantRemoved = "grant.removed";
    public const string RoleCreated = "role.created";
    public const string RoleUpdated = "role.updated";
    public const string GroupCreated = "group.created";
    public const string GroupUpdated = "group.updated";
    public const string GroupDeleted = "group.deleted";
    public const string MembershipAdded = "group.member.added";
    public const string MembershipRemoved = "group.member.removed";
    public const string DirectoryCreated = "directory.created";
    public const string DirectoryUpdated = "directory.updated";
    public const string DirectoriesReordered = "directory.reordered";
    public const string DirectoryDeleted = "directory.deleted";
    public const string AccountCreated = "account.created";
    public const string AccountLocked = "account.locked";
    public const string AccountUnlocked = "account.unlocked";
    public const string AccountMerged = "account.merged";
    public const string AddressAdded = "account.address.added";
    public const string AddressRemoved = "account.address.removed";
    public const string MailToChanged = "account.address.mail-to";
    public const string SignUpChanged = "settings.signup";
    public const string RetentionChanged = "settings.audit";
    public const string StepUpChanged = "settings.step-up";
    public const string StepUpSucceeded = "auth.step-up.succeeded";
    public const string StepUpFailed = "auth.step-up.failed";
    public const string StepUpEndedSession = "auth.step-up.session-ended";
    public const string TokenCreated = "token.created";
    public const string TokenRevoked = "token.revoked";
    public const string TokenSettingsChanged = "settings.tokens";

    /// <summary>A person signed out everywhere else, or an admin locked the account: its sessions ended.</summary>
    public const string SessionsEnded = "auth.sessions.ended";

    /// <summary>A person set a new password from a reset link: their sessions and tokens ended with the old one.</summary>
    public const string PasswordReset = "auth.password.reset";

    /// <summary>OAuth for agents: an MCP client registered itself, an admin made or removed an app.</summary>
    public const string OAuthAppRegistered = "oauth.app.registered";
    public const string OAuthAppCreated = "oauth.app.created";
    public const string OAuthAppDeleted = "oauth.app.deleted";

    /// <summary>A second factor: the second step at sign-in, set up, removed, an admin's reset, new recovery codes, a group's mode.</summary>
    public const string SecondFactorSucceeded = "auth.second-factor.succeeded";
    public const string SecondFactorFailed = "auth.second-factor.failed";
    public const string SecondFactorAdded = "account.second-factor.added";
    public const string SecondFactorRemoved = "account.second-factor.removed";
    public const string SecondFactorReset = "account.second-factor.reset";
    public const string RecoveryCodesRenewed = "account.recovery-codes.renewed";
    public const string GroupTwoFactor = "group.two-factor";

    /// <summary>A second step's code sent by email or a channel, and which methods the site allows.</summary>
    public const string SecondFactorCodeSent = "auth.second-factor.code-sent";
    public const string SecondFactorMethods = "settings.second-factor-methods";

    /// <summary>A person allowed an app to act for them, or took that back.</summary>
    public const string OAuthConsentGranted = "oauth.consent.granted";
    public const string OAuthConsentRevoked = "oauth.consent.revoked";

    /// <summary>What an admin recorded for a store of personal data, the site's controller and officer, and the record of processing downloaded.</summary>
    public const string PrivacyStore = "privacy.store";
    public const string PrivacySettings = "settings.privacy";
    public const string PrivacyRecordExported = "privacy.record.exported";

    /// <summary>A person's data exported: by themself, by an admin for an account, or for an address.</summary>
    public const string PrivacyExportSelf = "privacy.export.self";
    public const string PrivacyExportAccount = "privacy.export.account";
    public const string PrivacyExportAddress = "privacy.export.address";

    /// <summary>
    /// How an export written to the log as it began went: finished, with what it held, or aborted (the download was
    /// cut off, by the client or an error) after some of it may have gone out.
    /// </summary>
    public const string PrivacyExportEnded = "privacy.export.ended";
}

/// <summary>
/// Writes to the security audit (<c>guard.security_events</c>): sign-ins and their failures, what leaves the
/// site in bulk, and every change to who may do what, as whoever the request acts as. A change made in guard's database
/// is added to the same save as the change (<see cref="Add"/>); the rest commit on their own, whatever happens to the
/// work around them.
/// </summary>
[ExposeServices(typeof(SecurityLog), typeof(ISecurityAudit))]
public class SecurityLog(GuardDb guardDb, ActingContext acting) : ITransientDependency, ISecurityAudit
{
    /// <summary>A query's results downloaded as a file.</summary>
    public const string QueryExport = SecurityAuditTypes.QueryExport;

    private static readonly JsonSerializerOptions Json = JsonSerializerOptions.Web;

    public Task WriteAsync(string type, string? username, Guid? accountId, string? detail, string? ip, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            db.SecurityEvents.Add(new SecurityEvent(Guid.NewGuid(), type, username, accountId, detail, ip)
            {
                ActingAccountId = acting.ActorId,
                ActingMode = acting.Mode,
                SessionId = acting.SessionId,
            });
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken);

    /// <summary>A change made outside guard's database (a plugin installed), committed on its own.</summary>
    public Task WriteAsync(string type, AuditTarget? target, object? detail, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            Add(db, type, target, detail);
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken);

    /// <summary>A change to who may do what, saved with the change itself: both or neither.</summary>
    public void Add(GuardDbContext db, string type, AuditTarget? target, object? detail = null) =>
        db.SecurityEvents.Add(new SecurityEvent(Guid.NewGuid(), type, acting.SubjectName, acting.SubjectId,
            detail is null ? null : detail as string ?? JsonSerializer.Serialize(detail, Json), acting.Ip)
        {
            ActingAccountId = acting.ActorId,
            ActingMode = acting.Mode,
            SessionId = acting.SessionId,
            TargetType = target?.Type,
            TargetId = target?.Id,
            TargetName = target?.Name is { Length: > 256 } name ? name[..256] : target?.Name,
        });
}
