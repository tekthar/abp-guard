using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using AbpGuard.Data;
using AbpGuard.Domain;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services.Privacy;

/// <summary>
/// What Guard keeps about one person, for their export: their account and addresses as each directory
/// reports them, their groups and roles, their tokens and second factors (names and dates, never a secret or a hash),
/// where they're signed in and the apps they allowed, their own entries in the security log (without the names of the
/// people a change was made to), and what they recorded on the Privacy page. Someone outside the site has none of these.
/// </summary>
[ExposeServices(typeof(IPersonalDataExporter))]
public sealed class GuardPersonalDataExporter(GuardDb guardDb, OAuthApps apps, AccountSessions sessions) : IPersonalDataExporter, ITransientDependency
{
    public IReadOnlyList<string> Stores { get; } =
        ["guard.accounts", "guard.access", "guard.sign-in-secrets", "guard.sessions", "guard.security-log", "guard.privacy-record"];

    public async Task ExportAsync(IPersonalDataExport export, CancellationToken cancellationToken = default)
    {
        if (export.Subject.AccountId is not { } id)
        {
            return;
        }

        Dictionary<string, List<JsonObject>> files = await guardDb.RunAsync(db => ReadAsync(db, id, cancellationToken), cancellationToken: cancellationToken);
        // The phone app and scripts signed in as them now; a browser's sessions are in sessions.json, ended ones too.
        files["guard.sessions/app-sign-ins"] = [.. (await sessions.ListAsync(id, null, null, cancellationToken)).Where(s => s.Kind != SessionKinds.Browser)
            .Select(s => new JsonObject { ["kind"] = s.Kind, ["signedInAt"] = s.CreatedAt, ["lastSeenAt"] = s.LastSeenAt, ["endsAt"] = s.ExpiresAt })];
        files["guard.sessions/apps"] = [.. (await apps.GrantsAsync(id, cancellationToken)).Select(g => new JsonObject
        {
            ["app"] = g.AppName,
            ["access"] = g.Access,
            ["allowedAt"] = g.GrantedAt,
        })];

        foreach ((string path, List<JsonObject> rows) in files)
        {
            int slash = path.IndexOf('/');
            await export.WriteAsync(path[..slash], path[(slash + 1)..], PersonalDataRows.Of(rows), cancellationToken);
        }
    }

    private static async Task<Dictionary<string, List<JsonObject>>> ReadAsync(GuardDbContext db, Guid id, CancellationToken ct)
    {
        Account account = await db.Accounts.AsNoTracking().FirstAsync(a => a.Id == id, ct);
        Dictionary<Guid, string> directories = await db.Directories.AsNoTracking().ToDictionaryAsync(d => d.Id, d => d.Name, ct);
        List<DirectoryUser> records = await db.DirectoryUsers.AsNoTracking().Where(u => u.NormalizedUsername == account.NormalizedUsername).ToListAsync(ct);
        List<Guid> recordIds = [.. records.Select(r => r.Id)];
        Dictionary<Guid, string> groups = await db.Groups.AsNoTracking().ToDictionaryAsync(g => g.Id, g => g.Name, ct);
        Dictionary<Guid, string> roles = await db.Roles.AsNoTracking().ToDictionaryAsync(r => r.Id, r => r.Name, ct);

        return new Dictionary<string, List<JsonObject>>
        {
            ["guard.accounts/account"] =
            [
                new JsonObject
                {
                    ["username"] = account.Username,
                    ["displayName"] = account.DisplayName,
                    ["email"] = account.Email,
                    ["mailTo"] = account.MailTo,
                    ["status"] = account.Status.ToString(),
                    ["statusReason"] = account.StatusReason,
                    ["directory"] = directories.GetValueOrDefault(account.DirectoryId),
                    ["language"] = account.Language,
                    ["timeZone"] = account.TimeZone,
                    ["serviceAccount"] = account.IsService,
                    ["createdAt"] = account.CreatedAt,
                    ["lastSignedInAt"] = account.LastLoginAt,
                },
            ],
            ["guard.accounts/addresses"] = [.. (await db.AccountEmails.AsNoTracking().Where(e => e.AccountId == id).OrderBy(e => e.AddedAt).ToListAsync(ct))
                .Select(e => new JsonObject { ["email"] = e.Email, ["source"] = e.Source, ["verifiedAt"] = e.VerifiedAt, ["addedAt"] = e.AddedAt })],
            ["guard.accounts/directory-records"] = [.. records.Select(r => new JsonObject
            {
                ["directory"] = directories.GetValueOrDefault(r.DirectoryId),
                ["externalId"] = r.ExternalId,
                ["username"] = r.Username,
                ["displayName"] = r.DisplayName,
                ["email"] = r.Email,
                ["active"] = r.IsActive,
                ["signedUpAndUnconfirmedSince"] = r.PendingSince,
                ["lastSyncedAt"] = r.LastSyncedAt,
                ["createdAt"] = r.CreatedAt,
            })],
            ["guard.accounts/merged-into-yours"] = [.. (await db.Merges.AsNoTracking().Where(m => m.SurvivorId == id).OrderBy(m => m.StartedAt).ToListAsync(ct))
                .Select(m => new JsonObject
                {
                    ["username"] = m.SourceUsername,
                    ["displayName"] = m.SourceDisplayName,
                    ["email"] = m.SourceEmail,
                    ["reason"] = m.Reason,
                    ["mergedAt"] = m.StartedAt,
                })],
            ["guard.access/groups"] = [.. (await db.Memberships.AsNoTracking()
                    .Where(m => (m.MemberType == MemberType.Account && m.MemberId == id) || (m.MemberType == MemberType.DirectoryUser && recordIds.Contains(m.MemberId)))
                    .ToListAsync(ct))
                .Select(m => new JsonObject { ["group"] = groups.GetValueOrDefault(m.GroupId), ["source"] = m.Source.ToString(), ["since"] = m.CreatedAt })],
            ["guard.access/roles"] = [.. (await db.RoleGrants.AsNoTracking().Where(g => g.PrincipalType == PrincipalType.Account && g.PrincipalId == id).ToListAsync(ct))
                .Select(g => new JsonObject { ["role"] = roles.GetValueOrDefault(g.RoleId), ["scope"] = g.ScopeKey, ["until"] = g.ValidUntil, ["grantedAt"] = g.CreatedAt })],
            ["guard.sign-in-secrets/tokens"] = [.. (await db.PersonalAccessTokens.AsNoTracking().Where(t => t.AccountId == id).OrderBy(t => t.CreatedAt).ToListAsync(ct))
                .Select(t => new JsonObject
                {
                    ["name"] = t.Name,
                    ["access"] = t.Access,
                    ["createdAt"] = t.CreatedAt,
                    ["expiresAt"] = t.ExpiresAt,
                    ["lastUsedAt"] = t.LastUsedAt,
                    ["lastUsedFrom"] = t.LastUsedIp,
                    ["revokedAt"] = t.RevokedAt,
                })],
            ["guard.sign-in-secrets/second-factors"] = [.. (await db.SecondFactors.AsNoTracking().Where(f => f.AccountId == id).OrderBy(f => f.CreatedAt).ToListAsync(ct))
                .Select(f => new JsonObject { ["kind"] = f.Kind, ["setUpAt"] = f.ConfirmedAt ?? f.CreatedAt, ["lastUsedAt"] = f.LastUsedAt }),
                new JsonObject { ["recoveryCodesLeft"] = await db.RecoveryCodes.CountAsync(c => c.AccountId == id && c.UsedAt == null, ct) }],
            ["guard.sessions/sessions"] = [.. (await db.WebSessions.AsNoTracking().Where(s => s.AccountId == id).OrderBy(s => s.CreatedAt).ToListAsync(ct))
                .Select(s => new JsonObject
                {
                    ["browser"] = s.UserAgent,
                    ["from"] = s.Ip,
                    ["signedInAt"] = s.CreatedAt,
                    ["lastSeenAt"] = s.LastSeenAt,
                    ["endsAt"] = s.ExpiresAt,
                    ["endedAt"] = s.RevokedAt,
                })],
            // Their own entries: no names of the people a change was made to, and who acted for them only as a yes.
            ["guard.security-log/entries"] = [.. (await db.SecurityEvents.AsNoTracking().Where(e => e.AccountId == id).OrderBy(e => e.Time).ToListAsync(ct))
                .Select(e => new JsonObject
                {
                    ["at"] = e.Time,
                    ["what"] = e.Type,
                    ["from"] = e.Ip,
                    ["madeTo"] = e.TargetType,
                    ["bySomeoneActingForYou"] = e.ActingAccountId is { } actor && actor != id,
                })],
            ["guard.privacy-record/recorded"] = [.. (await db.PrivacyStores.AsNoTracking().Where(r => r.UpdatedBy == id).ToListAsync(ct))
                .Select(r => new JsonObject { ["store"] = r.StoreKey, ["recordedAt"] = r.UpdatedAt }),
                .. (await db.PrivacySettings.AsNoTracking().Where(s => s.UpdatedBy == id).ToListAsync(ct))
                .Select(s => new JsonObject { ["store"] = "the site's controller, officer and destinations", ["recordedAt"] = s.UpdatedAt })],
        };
    }
}
