using System.Text.Json.Serialization;
using Casl;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AbpGuard.Data;
using AbpGuard.Domain;
using Volo.Abp;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>Why a merge happened: an admin, or what found a placeholder's person.</summary>
public static class MergeReasons
{
    public const string Admin = "admin";
    public const string SignUp = "sign-up";
    public const string ConfirmedAddress = "confirmed-address";
    public const string AccountCreated = "account-created";
    public const string DirectorySync = "directory-sync";
    public const string AddressAdded = "address-added";
}

public sealed record MergeInput([property: JsonRequired] Guid SurvivorId, string? Confirm = null);

public sealed record MergeCountDto(string Key, int Count, string? Label);

/// <summary>What one module or plugin would move, or moved; a plugin's error when it couldn't say.</summary>
public sealed record MergePartDto(string Key, bool Plugin, List<MergeCountDto> Counts, string? Error);

/// <summary>
/// A merge before it happens: both accounts, whether the admin must confirm it by typing the source's username (it can
/// sign in), and what would move.
/// </summary>
public sealed record MergePreviewDto(AccountSummaryDto Source, AccountSummaryDto Survivor, bool NeedsConfirmation, bool SameDirectory, List<MergePartDto> Parts);

public sealed record AccountSummaryDto(Guid Id, string Username, string DisplayName, string? Email, string Status, string DirectoryName, DateTime? LastLoginAt);

public sealed record MergeStepDto(string Key, bool Plugin, string State, string? Error, DateTime At, List<MergeCountDto> Counts);

/// <summary>A merge as recorded. Actor is null when Guard merged a placeholder by itself (Reason says why).</summary>
public sealed record AccountMergeDto(
    Guid Id, Guid SourceId, string SourceUsername, string SourceDisplayName, string? SourceEmail, Guid SurvivorId, string SurvivorUsername,
    Guid? ActorId, string? ActorUsername, string Reason, bool Automatic, DateTime StartedAt, DateTime? FinishedAt, string State, List<MergeStepDto> Steps);

/// <summary>Accounts that share an address: one person twice, probably.</summary>
public sealed record DuplicateDto(string Email, List<AccountSummaryDto> Accounts);

/// <summary>
/// Folds one account into another. Guard, platform and every module's <see cref="IAccountMergeParticipant"/>
/// move their rows in one transaction; plugins' participants follow, each on its own, and a merge they didn't finish can
/// be resumed. The source stays: inactive, merged into the survivor, with its username.
/// </summary>
public class AccountMergeService(GuardDb guardDb, IGuardExtensions extensions, IServiceProvider services, IGuardEventSink events, ILogger<AccountMergeService> logger)
    : ITransientDependency
{
    public async Task<MergePreviewDto> PreviewAsync(Guid sourceId, Guid survivorId, Guid? actorId, CancellationToken ct)
    {
        (Account source, Account survivor, Dictionary<Guid, string> directories) = await guardDb.RunAsync(async db =>
        {
            (Account s, Account v) = await PairAsync(db, sourceId, survivorId, tracking: false, ct);
            Check(s, v, actorId);
            return (s, v, await db.Directories.ToDictionaryAsync(d => d.Id, d => d.Name, ct));
        }, cancellationToken: ct);

        List<MergePartDto> parts = [];
        parts.Add(new MergePartDto("guard", false, Dto(await guardDb.RunAsync(db => GuardCountsAsync(db, source, survivor, ct), cancellationToken: ct)), null));
        await using (IGuardLease<IAccountMergeParticipant> lease = extensions.Lease<IAccountMergeParticipant>(services))
        {
            foreach ((string? plugin, IAccountMergeParticipant participant) in lease.Items)
            {
                try
                {
                    IReadOnlyList<AccountMergeCount> counts = await guardDb.RunAsync(_ => participant.PreviewAsync(sourceId, survivorId, ct), cancellationToken: ct);
                    parts.Add(new MergePartDto(plugin ?? HostKey(participant), plugin is not null, Dto(counts), null));
                }
                catch (Exception ex) when (plugin is not null)
                {
                    parts.Add(new MergePartDto(plugin, true, [], ex.Message));
                }
            }
        }

        return new MergePreviewDto(Summary(source, directories), Summary(survivor, directories), source.Status == AccountStatus.Active,
            source.DirectoryId == survivor.DirectoryId, parts);
    }

    /// <summary>
    /// Merges source into survivor. Actor is the admin (null for an automatic merge); an active source needs confirm to be
    /// its username.
    /// </summary>
    public async Task<AccountMergeDto> MergeAsync(Guid sourceId, Guid survivorId, Guid? actorId, string reason, string? confirm, CancellationToken ct)
    {
        await using IGuardLease<IAccountMergeParticipant> lease = extensions.Lease<IAccountMergeParticipant>(services);
        List<(string Key, IAccountMergeParticipant Participant)> host = lease.Items.Where(i => i.PluginKey is null).Select(i => (HostKey(i.Instance), i.Instance)).ToList();
        List<(string Key, IAccountMergeParticipant Participant)> plugins = lease.Items.Where(i => i.PluginKey is not null).Select(i => (i.PluginKey!, i.Instance)).ToList();

        (AccountMergeRecord record, AccountMerge merge, bool wasActive) = await guardDb.RunAsync(async db =>
        {
            // Two merges of the same accounts wait for each other, and the second sees what the first did.
            await db.Database.ExecuteSqlInterpolatedAsync($"""SELECT 1 FROM guard.accounts WHERE "Id" IN ({sourceId}, {survivorId}) FOR UPDATE""", ct);
            (Account source, Account survivor) = await PairAsync(db, sourceId, survivorId, tracking: true, ct);
            Check(source, survivor, actorId);
            if (source.Status == AccountStatus.Active && actorId is not null
                && !string.Equals(confirm?.Trim(), source.Username, StringComparison.OrdinalIgnoreCase))
            {
                throw new UserFriendlyException($"{source.Username} can sign in. To merge it into {survivor.Username}, confirm with its username.");
            }

            bool wasActive = source.Status == AccountStatus.Active;
            AccountMergeRecord record = db.Merges.Add(new AccountMergeRecord(Guid.NewGuid(), source, survivor, actorId, reason)).Entity;
            AccountMerge merge = new(record.Id, source.Id, source.Username, survivor.Id, survivor.Username, survivor.DisplayName);
            List<MergeStep> steps = [];
            foreach ((string key, IAccountMergeParticipant participant) in host)
            {
                steps.Add(Step(key, false, await participant.MergeAsync(merge, ct))); // same unit of work: same transaction
            }

            // Guard's own rows last: writing grants, memberships and accounts locks the permission stamp until
            // the transaction commits, so it's held for as short a time as possible.
            steps.Insert(0, Step("guard", false, await GuardMergeAsync(db, source, survivor, actorId, ct)));

            steps.AddRange(plugins.Select(p => new MergeStep { Key = p.Key, Plugin = true, State = "pending", At = DateTime.UtcNow }));
            record.Steps = steps;
            Finish(record);
            string detail = $"{source.Username} merged into {survivor.Username}" + (actorId is null ? $" automatically ({reason})" : "");
            db.SecurityEvents.Add(new SecurityEvent(Guid.NewGuid(), "account.merged", source.Username, source.Id, detail, null));
            db.SecurityEvents.Add(new SecurityEvent(Guid.NewGuid(), "account.merged", survivor.Username, survivor.Id, detail, null));
            await db.SaveChangesAsync(ct);
            await Organizations.ApplyDomainsAsync(db, ct); // the survivor's addresses grew; the source's are gone
            // In the merge's unit of work: the events commit with it.
            if (wasActive)
            {
                await events.PublishAsync(new AccountDeactivatedEto(merge.SourceId, merge.SourceUsername, $"Merged into {merge.SurvivorUsername}"), ct);
            }

            await events.PublishAsync(new AccountMergedEto(record.Id, merge.SourceId, merge.SourceUsername, merge.SurvivorId, merge.SurvivorUsername, actorId is null), ct);
            return (record, merge, wasActive);
        }, requiresNew: true, ct, isTransactional: true);

        await RunPluginsAsync(record.Id, merge, plugins, ct);
        return await GetAsync(record.Id, ct);
    }

    /// <summary>Asks the plugins that haven't finished a merge (they failed, or were off) to move their rows now.</summary>
    public async Task<AccountMergeDto> ResumeAsync(Guid mergeId, CancellationToken ct)
    {
        AccountMergeRecord record = await guardDb.RunAsync(db => db.Merges.AsNoTracking().FirstOrDefaultAsync(m => m.Id == mergeId, ct), cancellationToken: ct)
            ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(AccountMergeRecord), mergeId);
        string survivorName = await guardDb.RunAsync(db => db.Accounts.Where(a => a.Id == record.SurvivorId).Select(a => a.DisplayName).FirstAsync(ct), cancellationToken: ct);
        AccountMerge merge = new(record.Id, record.SourceId, record.SourceUsername, record.SurvivorId, record.SurvivorUsername, survivorName);
        await using IGuardLease<IAccountMergeParticipant> lease = extensions.Lease<IAccountMergeParticipant>(services);
        // Every enabled plugin with a participant is asked again unless it finished: one that was off when the merge ran
        // has no step yet. Moving is safe to repeat, so asking twice does no harm.
        HashSet<string> finished = record.Steps.Where(s => s.Plugin && s.State == "done").Select(s => s.Key).ToHashSet();
        List<(string Key, IAccountMergeParticipant Participant)> plugins = lease.Items
            .Where(i => i.PluginKey is not null && !finished.Contains(i.PluginKey))
            .Select(i => (i.PluginKey!, i.Instance)).ToList();
        await RunPluginsAsync(record.Id, merge, plugins, ct);
        return await GetAsync(record.Id, ct);
    }

    /// <summary>
    /// Merges each placeholder into the one active account that has its address, verified. Run when
    /// an account appears or an address is verified; nothing happens for an address more than one account has.
    /// </summary>
    public async Task<int> FoldPlaceholdersAsync(string reason, CancellationToken ct)
    {
        List<(Guid Placeholder, Guid Survivor)> pairs = await guardDb.RunAsync(async db =>
        {
            var placeholders = await Addresses.Placeholders(db).Where(a => a.Email != null).Select(a => new { a.Id, a.Email }).ToListAsync(ct);
            if (placeholders.Count == 0)
            {
                return [];
            }

            List<string> wanted = placeholders.Select(p => GuardConstants.Normalize(p.Email!)).Distinct().ToList();
            IQueryable<Account> real = Addresses.NotPlaceholders(db, db.Accounts.Where(a => a.MergedIntoId == null && a.Status == AccountStatus.Active));
            var byDirectory = await real.Where(a => a.Email != null && wanted.Contains(a.Email.ToLower())).Select(a => new { a.Id, Email = a.Email!.ToLower() }).ToListAsync(ct);
            var byOwn = await db.AccountEmails.Where(e => e.VerifiedAt != null && wanted.Contains(e.NormalizedEmail) && real.Any(a => a.Id == e.AccountId))
                .Select(e => new { Id = e.AccountId, Email = e.NormalizedEmail }).ToListAsync(ct);
            Dictionary<string, List<Guid>> owners = byDirectory.Concat(byOwn).GroupBy(x => x.Email).ToDictionary(g => g.Key, g => g.Select(x => x.Id).Distinct().ToList());
            return placeholders
                .Select(p => (p.Id, owners.GetValueOrDefault(GuardConstants.Normalize(p.Email!))))
                .Where(p => p.Item2 is [_])
                .Select(p => (p.Id, p.Item2![0]))
                .ToList();
        }, cancellationToken: ct);

        int merged = 0;
        foreach ((Guid placeholder, Guid survivor) in pairs)
        {
            try
            {
                await MergeAsync(placeholder, survivor, actorId: null, reason, confirm: null, ct);
                merged++;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "The placeholder {Placeholder} couldn't be merged into {Survivor}", placeholder, survivor);
            }
        }

        return merged;
    }

    public Task<AccountMergeDto> GetAsync(Guid mergeId, CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        AccountMergeRecord record = await db.Merges.AsNoTracking().FirstOrDefaultAsync(m => m.Id == mergeId, ct)
            ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(AccountMergeRecord), mergeId);
        return (await DtosAsync(db, [record], ct))[0];
    }, cancellationToken: ct);

    /// <summary>Merges, newest first: all of them, or those an account was in (as source or survivor).</summary>
    /// <summary>The newest merges, of an account or all; with <paramref name="within"/>, only those whose two accounts it may merge (in SQL).</summary>
    public Task<List<AccountMergeDto>> ListAsync(Guid? accountId, int take, CancellationToken ct, Casl.Ability? within = null) => guardDb.RunAsync(async db =>
    {
        IQueryable<AccountMergeRecord> query = db.Merges.AsNoTracking();
        if (accountId is { } id)
        {
            query = query.Where(m => m.SourceId == id || m.SurvivorId == id);
        }

        if (within is not null)
        {
            IQueryable<Guid> mergeable = db.Accounts.AsNoTracking().AccessibleBy(within, "merge").Select(a => a.Id);
            query = query.Where(m => mergeable.Contains(m.SourceId) && mergeable.Contains(m.SurvivorId));
        }

        return await DtosAsync(db, await query.OrderByDescending(m => m.StartedAt).Take(Math.Clamp(take, 1, 500)).ToListAsync(ct), ct);
    }, cancellationToken: ct);

    /// <summary>Addresses more than one account has (the directory's or verified), placeholders included; merged accounts aren't.</summary>
    public Task<List<DuplicateDto>> DuplicatesAsync(CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        var byDirectory = await db.Accounts.AsNoTracking().Where(a => a.MergedIntoId == null && a.Email != null).Select(a => new { a.Id, Email = a.Email!.ToLower() }).ToListAsync(ct);
        var byOwn = await db.AccountEmails.AsNoTracking().Where(e => e.VerifiedAt != null && db.Accounts.Any(a => a.Id == e.AccountId && a.MergedIntoId == null))
            .Select(e => new { Id = e.AccountId, Email = e.NormalizedEmail }).ToListAsync(ct);
        List<(string Email, List<Guid> Ids)> shared = byDirectory.Concat(byOwn).GroupBy(x => x.Email)
            .Select(g => (g.Key, g.Select(x => x.Id).Distinct().ToList()))
            .Where(g => g.Item2.Count > 1)
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .Take(200)
            .ToList();
        List<Guid> ids = shared.SelectMany(s => s.Ids).Distinct().ToList();
        Dictionary<Guid, Account> accounts = await db.Accounts.AsNoTracking().Where(a => ids.Contains(a.Id)).ToDictionaryAsync(a => a.Id, ct);
        Dictionary<Guid, string> directories = await db.Directories.ToDictionaryAsync(d => d.Id, d => d.Name, ct);
        return shared.Select(s => new DuplicateDto(s.Email, s.Ids.Select(id => Summary(accounts[id], directories))
                .OrderBy(a => a.Status == nameof(AccountStatus.Active) ? 0 : 1).ThenBy(a => a.Username, StringComparer.Ordinal).ToList()))
            .ToList();
    }, cancellationToken: ct);

    private async Task RunPluginsAsync(Guid mergeId, AccountMerge merge, List<(string Key, IAccountMergeParticipant Participant)> plugins, CancellationToken ct)
    {
        foreach ((string key, IAccountMergeParticipant participant) in plugins)
        {
            MergeStep step = new() { Key = key, Plugin = true, At = DateTime.UtcNow };
            try
            {
                step.Counts = Counts(await participant.MergeAsync(merge, ct));
                step.State = "done";
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Plugin {Plugin} couldn't move its rows for merge {Merge}", key, mergeId);
                (step.State, step.Error) = ("failed", ex.Message);
            }

            await guardDb.RunAsync(async db =>
            {
                AccountMergeRecord record = await db.Merges.FirstAsync(m => m.Id == mergeId, ct);
                record.Steps = record.Steps.Where(s => s.Key != key).Append(step).ToList();
                Finish(record);
                await db.SaveChangesAsync(ct);
            }, requiresNew: true, ct);
        }
    }

    /// <summary>Done once every step is: the host's own always are when the transaction commits.</summary>
    private static void Finish(AccountMergeRecord record)
    {
        bool done = record.Steps.All(s => s.State == "done");
        record.State = done ? MergeStates.Done : MergeStates.Incomplete;
        record.FinishedAt = done ? record.FinishedAt ?? DateTime.UtcNow : null;
    }

    private static async Task<(Account Source, Account Survivor)> PairAsync(GuardDbContext db, Guid sourceId, Guid survivorId, bool tracking, CancellationToken ct)
    {
        IQueryable<Account> accounts = tracking ? db.Accounts : db.Accounts.AsNoTracking();
        Account source = await accounts.FirstOrDefaultAsync(a => a.Id == sourceId, ct) ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(Account), sourceId);
        Account survivor = await accounts.FirstOrDefaultAsync(a => a.Id == survivorId, ct) ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(Account), survivorId);
        return (source, survivor);
    }

    /// <summary>What a merge never does.</summary>
    private static void Check(Account source, Account survivor, Guid? actorId)
    {
        if (source.Id == survivor.Id)
        {
            throw new UserFriendlyException("An account can't be merged into itself.");
        }

        if (source.Id == GuardConstants.AnonymousId || survivor.Id == GuardConstants.AnonymousId)
        {
            throw new UserFriendlyException("Anonymous visitors aren't an account to merge.");
        }

        if (source.MergedIntoId is not null)
        {
            throw new UserFriendlyException($"{source.Username} was merged into another account already.");
        }

        if (survivor.MergedIntoId is not null)
        {
            throw new UserFriendlyException($"{survivor.Username} was merged into another account: merge into that one instead.");
        }

        if (actorId == source.Id)
        {
            throw new UserFriendlyException("You can't merge your own account into another. Ask another administrator, or merge the other account into yours.");
        }
    }

    /// <summary>
    /// Guard's own rows: grants and memberships added in Guard move (a duplicate of what the survivor has goes); the source's
    /// addresses become the survivor's, verified; its sign-ins end; accounts merged into it follow it to the survivor.
    /// </summary>
    private static async Task<List<AccountMergeCount>> GuardMergeAsync(GuardDbContext db, Account source, Account survivor, Guid? actorId, CancellationToken ct)
    {
        List<AccountMergeCount> counts = [];

        // Grants: the survivor keeps one per role and scope, valid for the longer of the two.
        List<RoleGrant> theirs = await db.RoleGrants.Where(g => g.PrincipalType == PrincipalType.Account && g.PrincipalId == source.Id).ToListAsync(ct);
        List<RoleGrant> ours = await db.RoleGrants.Where(g => g.PrincipalType == PrincipalType.Account && g.PrincipalId == survivor.Id).ToListAsync(ct);
        int grants = 0;
        foreach (RoleGrant grant in theirs)
        {
            RoleGrant? same = ours.FirstOrDefault(g => g.RoleId == grant.RoleId && g.ScopeKey == grant.ScopeKey && g.ScopeJson == grant.ScopeJson);
            if (same is not null)
            {
                same.ValidUntil = same.ValidUntil is null || grant.ValidUntil is null ? null : Max(same.ValidUntil.Value, grant.ValidUntil.Value);
                db.RoleGrants.Remove(grant);
            }
            else
            {
                await db.RoleGrants.Where(g => g.Id == grant.Id).ExecuteUpdateAsync(s => s.SetProperty(g => g.PrincipalId, survivor.Id), ct);
            }

            grants++;
        }

        counts.Add(new("grants", grants));
        await db.RoleGrants.Where(g => g.CreatedBy == source.Id).ExecuteUpdateAsync(s => s.SetProperty(g => g.CreatedBy, survivor.Id), ct);

        // Memberships added in Guard; organizations by domain are worked out again once the addresses have moved.
        List<GroupMembership> memberships = await db.Memberships.Where(m => m.MemberType == MemberType.Account && m.MemberId == source.Id).ToListAsync(ct);
        HashSet<Guid> alreadyIn = (await db.Memberships.Where(m => m.MemberType == MemberType.Account && m.MemberId == survivor.Id && m.Source == MembershipSource.Manual)
            .Select(m => m.GroupId).ToListAsync(ct)).ToHashSet();
        int moved = 0;
        foreach (GroupMembership membership in memberships)
        {
            if (membership.Source == MembershipSource.Manual && !alreadyIn.Contains(membership.GroupId))
            {
                await db.Memberships.Where(m => m.Id == membership.Id).ExecuteUpdateAsync(s => s.SetProperty(m => m.MemberId, survivor.Id), ct);
            }
            else
            {
                db.Memberships.Remove(membership);
            }

            moved += membership.Source == MembershipSource.Manual ? 1 : 0;
        }

        counts.Add(new("memberships", moved));

        // Addresses: the source's directory address and its verified ones become the survivor's, unless the survivor has
        // them already or a third account does (then they're dropped, and the duplicates list shows them).
        Dictionary<Guid, HashSet<string>> have = await Addresses.OfAsync(db, [survivor.Id], ct);
        List<AccountEmail> sourceRows = await db.AccountEmails.Where(e => e.AccountId == source.Id).ToListAsync(ct);
        List<AccountEmail> survivorRows = await db.AccountEmails.Where(e => e.AccountId == survivor.Id).ToListAsync(ct);
        List<(string Email, AccountEmail? Row)> addresses = sourceRows.Where(e => e.VerifiedAt is not null).Select(e => (e.Email, (AccountEmail?)e)).ToList();
        if (source.Email is { Length: > 0 } directoryEmail && Addresses.Normalize(directoryEmail) is { } directory
            && addresses.All(a => GuardConstants.Normalize(a.Email) != directory))
        {
            addresses.Insert(0, (directoryEmail, null));
        }

        int taken = 0;
        foreach ((string email, AccountEmail? row) in addresses)
        {
            string normalized = GuardConstants.Normalize(email);
            bool elsewhere = await Addresses.WithAddress(db, normalized).AnyAsync(a => a.Id != source.Id && a.Id != survivor.Id, ct);
            if (have[survivor.Id].Contains(normalized) || elsewhere)
            {
                continue;
            }

            have[survivor.Id].Add(normalized);
            taken++;
            if (survivorRows.FirstOrDefault(e => e.NormalizedEmail == normalized) is { } waiting)
            {
                // The survivor asked for it and was waiting for the link: the merge settles it. The source's own row goes
                // first, so the address is never verified twice.
                if (row is not null)
                {
                    await db.AccountEmails.Where(e => e.Id == row.Id).ExecuteDeleteAsync(ct);
                    sourceRows.Remove(row);
                }

                waiting.VerifiedAt = DateTime.UtcNow;
                continue;
            }

            if (row is not null)
            {
                await db.AccountEmails.Where(e => e.Id == row.Id).ExecuteUpdateAsync(s => s.SetProperty(e => e.AccountId, survivor.Id), ct);
                sourceRows.Remove(row);
            }
            else
            {
                db.AccountEmails.Add(new AccountEmail(Guid.NewGuid(), survivor.Id, email, AccountEmailSources.Merge, actorId) { VerifiedAt = DateTime.UtcNow });
            }
        }

        db.AccountEmails.RemoveRange(sourceRows); // the rest: waiting for a link, or someone else's
        counts.Add(new("addresses", taken));

        // The source: inactive for good, pointing at the survivor; and anything merged into it points there too.
        source.MergedIntoId = survivor.Id;
        source.Status = AccountStatus.Inactive;
        source.StatusReason = $"Merged into {survivor.Username}";
        source.MailTo = null;
        await db.Accounts.Where(a => a.MergedIntoId == source.Id).ExecuteUpdateAsync(s => s
            .SetProperty(a => a.MergedIntoId, survivor.Id)
            .SetProperty(a => a.StatusReason, $"Merged into {survivor.Username}"), ct);

        // Its sign-ins end now, not when their tokens run out.
        string subject = source.Id.ToString();
        await db.Database.ExecuteSqlInterpolatedAsync($"""UPDATE guard.oidc_tokens SET "Status" = 'revoked' WHERE "Subject" = {subject} AND "Status" <> 'revoked'""", ct);
        await db.Database.ExecuteSqlInterpolatedAsync($"""UPDATE guard.oidc_authorizations SET "Status" = 'revoked' WHERE "Subject" = {subject} AND "Status" <> 'revoked'""", ct);

        // So do its access tokens: each was made for its rights, so it isn't handed to the survivor. Tokens it made or
        // revoked for others, and addresses it added, are the survivor's doing now.
        DateTime now = DateTime.UtcNow;
        counts.Add(new("tokens", await db.PersonalAccessTokens.Where(t => t.AccountId == source.Id && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, now).SetProperty(t => t.RevokedBy, actorId), ct)));
        await db.PersonalAccessTokens.Where(t => t.CreatedBy == source.Id).ExecuteUpdateAsync(s => s.SetProperty(t => t.CreatedBy, survivor.Id), ct);
        await db.PersonalAccessTokens.Where(t => t.RevokedBy == source.Id).ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedBy, survivor.Id), ct);

        // And its browsers' sessions, which a person signs in to again as the survivor.
        await db.WebSessions.Where(s => s.AccountId == source.Id && s.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, now).SetProperty(x => x.RevokedReason, "merged"), ct);
        await db.AccountEmails.Where(e => e.AddedBy == source.Id).ExecuteUpdateAsync(s => s.SetProperty(e => e.AddedBy, survivor.Id), ct);

        // Its second factors and recovery codes go: they were set up for its sign-in, which has ended, and the
        // survivor keeps its own. So do its sign-ins still waiting for their second step.
        await db.SecondFactors.Where(f => f.AccountId == source.Id).ExecuteDeleteAsync(ct);
        await db.RecoveryCodes.Where(c => c.AccountId == source.Id).ExecuteDeleteAsync(ct);
        await db.SignInTickets.Where(t => t.AccountId == source.Id).ExecuteDeleteAsync(ct);
        await db.SentCodes.Where(c => c.AccountId == source.Id).ExecuteDeleteAsync(ct);
        return counts;
    }

    private static async Task<IReadOnlyList<AccountMergeCount>> GuardCountsAsync(GuardDbContext db, Account source, Account survivor, CancellationToken ct)
    {
        int grants = await db.RoleGrants.CountAsync(g => g.PrincipalType == PrincipalType.Account && g.PrincipalId == source.Id, ct);
        int memberships = await db.Memberships.CountAsync(m => m.MemberType == MemberType.Account && m.MemberId == source.Id && m.Source == MembershipSource.Manual, ct);
        Dictionary<Guid, HashSet<string>> addresses = await Addresses.OfAsync(db, [source.Id, survivor.Id], ct);
        DateTime now = DateTime.UtcNow;
        int tokens = await db.PersonalAccessTokens.CountAsync(t => t.AccountId == source.Id && t.RevokedAt == null && t.ExpiresAt > now, ct);
        return [new("grants", grants), new("memberships", memberships), new("addresses", addresses[source.Id].Except(addresses[survivor.Id]).Count()), new("tokens", tokens)];
    }

    private static async Task<List<AccountMergeDto>> DtosAsync(GuardDbContext db, List<AccountMergeRecord> records, CancellationToken ct)
    {
        List<Guid> actors = records.Where(r => r.ActorId is not null).Select(r => r.ActorId!.Value).Distinct().ToList();
        Dictionary<Guid, string> names = await db.Accounts.AsNoTracking().Where(a => actors.Contains(a.Id)).ToDictionaryAsync(a => a.Id, a => a.Username, ct);
        return records.Select(r => new AccountMergeDto(r.Id, r.SourceId, r.SourceUsername, r.SourceDisplayName, r.SourceEmail, r.SurvivorId, r.SurvivorUsername,
                r.ActorId, r.ActorId is { } a ? names.GetValueOrDefault(a) : null, r.Reason, r.ActorId is null, r.StartedAt, r.FinishedAt, r.State,
                r.Steps.Select(s => new MergeStepDto(s.Key, s.Plugin, s.State, s.Error, s.At, s.Counts.Select(c => new MergeCountDto(c.Key, c.Count, c.Label)).ToList())).ToList()))
            .ToList();
    }

    private static MergeStep Step(string key, bool plugin, IReadOnlyList<AccountMergeCount> counts) =>
        new() { Key = key, Plugin = plugin, State = "done", At = DateTime.UtcNow, Counts = Counts(counts) };

    private static List<MergeStepCount> Counts(IReadOnlyList<AccountMergeCount> counts) =>
        counts.Where(c => c.Count > 0).Select(c => new MergeStepCount { Key = c.Key, Count = c.Count, Label = c.Label }).ToList();

    private static List<MergeCountDto> Dto(IReadOnlyList<AccountMergeCount> counts) =>
        counts.Where(c => c.Count > 0).Select(c => new MergeCountDto(c.Key, c.Count, c.Label)).ToList();

    internal static AccountSummaryDto Summary(Account a, IReadOnlyDictionary<Guid, string> directories) =>
        new(a.Id, a.Username, a.DisplayName, a.Email, a.Status.ToString(), directories.GetValueOrDefault(a.DirectoryId, "?"), a.LastLoginAt);

    /// <summary>A module's key from its namespace: MyHost.Projects.… is "projects".</summary>
    private static string HostKey(IAccountMergeParticipant participant) =>
        (participant.GetType().Namespace ?? "host").Split('.') is [_, var module, ..] ? module.ToLowerInvariant() : "host";

    private static DateTime Max(DateTime a, DateTime b) => a > b ? a : b;
}
