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

    /// <summary>A correction: an internal account's display name, or which confirmed address is its primary.</summary>
    public const string AccountRenamed = "account.renamed";

    /// <summary>A service account's picture set or cleared.</summary>
    public const string AccountPictureChanged = "account.picture";
    public const string PrimaryAddressChanged = "account.address.primary";
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

    /// <summary>
    /// Erasure: a person asked, an admin declined, an account or an address was erased (or the erasure
    /// stopped at a store and was resumed, or went on without a plugin's store), and legal holds put on and released.
    /// </summary>
    public const string ErasureRequested = "privacy.erasure.requested";
    public const string ErasureDeclined = "privacy.erasure.declined";
    public const string AccountErased = "privacy.erasure.account";
    public const string AddressErased = "privacy.erasure.address";
    public const string ErasureResumed = "privacy.erasure.resumed";
    public const string ErasureStoreSkipped = "privacy.erasure.store-skipped";
    public const string LegalHoldAdded = "privacy.hold.added";
    public const string LegalHoldReleased = "privacy.hold.released";

    /// <summary>Retention: its periods set or confirmed, and a sweep with how many rows each rule removed.</summary>
    public const string Retention = "settings.retention";
    public const string RetentionSwept = "privacy.retention.swept";

    /// <summary>The privacy notice: a version published, accepted by a person signed in; consent withdrawn, and handled.</summary>
    public const string NoticePublished = "privacy.notice.published";
    public const string NoticeAccepted = "privacy.notice.accepted";
    public const string ConsentWithdrawn = "privacy.consent.withdrawn";
    public const string ConsentHandled = "privacy.consent.handled";

    /// <summary>Whether apps may register themselves, turned on or off.</summary>
    public const string AppsMayRegister = "settings.apps-register";

    /// <summary>Breaches: the log downloaded, its feed set, an alert told to site admins.</summary>
    public const string LogExported = "security.log.exported";
    public const string FeedChanged = "settings.security-feed";
    public const string AlertSent = "security.alert.sent";
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
