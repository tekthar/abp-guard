using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using AbpGuard.Domain;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services.Privacy;

/// <summary>
/// Guard's retention rules: someone who signed up and never confirmed goes after a week, with their
/// account; apps' sign-ins and tokens go a month after they ended (expired or revoked), through OpenIddict's own pruning;
/// the network address a notice was accepted from goes after a year, the acceptance (who, which version, where, when) stays.
/// The security log has its own period (Administration › Security), and browsers' sessions go a month after they end.
/// </summary>
[ExposeServices(typeof(IPersonalDataSweeper))]
public sealed class GuardRetention(GuardDb guardDb, AccountProjector projector, IOpenIddictTokenManager tokens, IOpenIddictAuthorizationManager authorizations)
    : IPersonalDataSweeper, ITransientDependency
{
    public const string UnconfirmedSignUps = "guard.unconfirmed-sign-ups";
    public const string AppSignIns = "guard.app-sign-ins";
    public const string ConsentAddresses = "guard.consent-ips";

    public IReadOnlyList<RetentionRule> Rules { get; } =
    [
        new(UnconfirmedSignUps, "guard.accounts", new("Sign-ups never confirmed", "تسجيلات لم تُؤكَّد"), 7, 1, 90),
        new(AppSignIns, "guard.sessions", new("Apps' sign-ins after they end", "عمليات دخول التطبيقات بعد انتهائها"), 30, 1, 365),
        new(ConsentAddresses, "guard.consent", new("Where a notice was accepted from (the network address)", "العنوان الشبكي الذي قُبل منه الإشعار"), 365, 30, 1825),
    ];

    public Task<int> SweepAsync(string rule, DateTime before, int batch, CancellationToken cancellationToken = default) => rule switch
    {
        UnconfirmedSignUps => SignUpsAsync(before, batch, cancellationToken),
        AppSignIns => AppSignInsAsync(before, cancellationToken),
        ConsentAddresses => guardDb.RunAsync(db => db.PrivacyAcceptances.Where(a => a.Ip != null && a.At < before).OrderBy(a => a.At).Take(batch)
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.Ip, (string?)null), cancellationToken), requiresNew: true, cancellationToken),
        _ => Task.FromResult(0),
    };

    /// <summary>
    /// A sign-up's record still waiting for its link, and the account it made. Only an account no other record holds goes
    /// (never signed in, inactive, not a service account): a placeholder from an import with the same username keeps its
    /// account, which a rebuild gives back to its own record. No host heard of a pending account (sign-up keeps the
    /// rebuild's events to itself until the address is confirmed), so none is told it went.
    /// </summary>
    private Task<int> SignUpsAsync(DateTime before, int batch, CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        List<DirectoryUser> pending = await db.DirectoryUsers.Where(u => u.PendingSince != null && u.PendingSince < before).OrderBy(u => u.PendingSince)
            .Take(batch).ToListAsync(ct);
        List<Guid> records = [.. pending.Select(u => u.Id)];
        List<string> usernames = [.. pending.Select(u => u.NormalizedUsername).Distinct()];
        HashSet<string> heldElsewhere = [.. await db.DirectoryUsers.Where(u => usernames.Contains(u.NormalizedUsername) && !records.Contains(u.Id))
            .Select(u => u.NormalizedUsername).Distinct().ToListAsync(ct)];
        List<Guid> accounts = [.. (await db.Accounts.Where(a => a.DirectoryUserId != null && records.Contains(a.DirectoryUserId.Value)
                && a.Status != AccountStatus.Active && !a.IsService && a.LastLoginAt == null && a.MergedIntoId == null)
            .Select(a => new { a.Id, a.NormalizedUsername }).ToListAsync(ct)).Where(a => !heldElsewhere.Contains(a.NormalizedUsername)).Select(a => a.Id)];
        await db.Memberships.Where(m => (m.MemberType == MemberType.Account && accounts.Contains(m.MemberId))
            || (m.MemberType == MemberType.DirectoryUser && records.Contains(m.MemberId))).ExecuteDeleteAsync(ct);
        await db.RoleGrants.Where(g => g.PrincipalType == PrincipalType.Account && accounts.Contains(g.PrincipalId)).ExecuteDeleteAsync(ct);
        await db.AccountEmails.Where(e => accounts.Contains(e.AccountId)).ExecuteDeleteAsync(ct);
        await db.PersonalAccessTokens.Where(t => accounts.Contains(t.AccountId)).ExecuteDeleteAsync(ct);
        await db.SecondFactors.Where(f => accounts.Contains(f.AccountId)).ExecuteDeleteAsync(ct);
        await db.RecoveryCodes.Where(c => accounts.Contains(c.AccountId)).ExecuteDeleteAsync(ct);
        await db.SentCodes.Where(c => accounts.Contains(c.AccountId)).ExecuteDeleteAsync(ct);
        await db.SignInTickets.Where(t => accounts.Contains(t.AccountId)).ExecuteDeleteAsync(ct);
        await db.WebSessions.Where(w => accounts.Contains(w.AccountId)).ExecuteDeleteAsync(ct);
        await db.Accounts.Where(a => accounts.Contains(a.Id)).ExecuteDeleteAsync(ct);
        db.DirectoryUsers.RemoveRange(pending);
        await db.SaveChangesAsync(ct);
        if (heldElsewhere.Count > 0)
        {
            await projector.RebuildAsync(db, [.. heldElsewhere], ct);
            await db.SaveChangesAsync(ct);
        }

        return pending.Count;
    }, requiresNew: true, ct, isTransactional: true);

    /// <summary>Tokens and permissions no longer good (expired, revoked, ended), made before the period: OpenIddict prunes them.</summary>
    private async Task<int> AppSignInsAsync(DateTime before, CancellationToken ct)
    {
        DateTimeOffset threshold = new(before, TimeSpan.Zero);
        long removed = await tokens.PruneAsync(threshold, ct) + await authorizations.PruneAsync(threshold, ct);
        return (int)Math.Min(removed, PersonalDataRetention.Batch - 1); // pruned whole: one call
    }
}
