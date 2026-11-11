using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using AbpGuard.Data;
using AbpGuard.Domain;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services.Privacy;

/// <summary>
/// Guard's own part of an erasure, run last by <see cref="PersonalDataErasures"/> once every other
/// store is done, because it removes what finds the person. The account stays, so history keeps pointing at someone,
/// but as its pseudonym: "Former person {n}", inactive for good, with no address. Its sign-ins end; its sessions,
/// tokens, second factors, codes, added addresses, groups, roles and directory records go; the accounts merged into
/// it go the same way. The security log keeps its entries (what happened, when, from which address) with the person's
/// names replaced by the pseudonym, and so do merge records. Events about them still waiting in the outbox go (one
/// sent is gone from it already); the counts against abuse are hashes kept a day, which nothing ties back to them.
/// Someone outside the site: only their addresses in the log and in released legal holds. What the security log's feed
/// already sent to its receiver can't be recalled from here: the site asks the receiver.
/// </summary>
[ExposeServices(typeof(IPersonalDataEraser), typeof(GuardPersonalDataEraser))]
public sealed class GuardPersonalDataEraser(GuardDb guardDb, AccountSessions sessions, IOpenIddictAuthorizationManager authorizations,
    IOpenIddictTokenManager tokens) : IPersonalDataEraser, ITransientDependency
{
    public const string ErasedReason = "Erased";

    public IReadOnlyList<string> Stores { get; } =
    [
        "guard.accounts", "guard.access", "guard.sign-in-secrets", "guard.sessions", "guard.security-log", "guard.privacy-record", "guard.events",
        "guard.limits", "guard.erasures", "guard.consent",
    ];

    public async Task EraseAsync(PersonalDataErasure erasure, CancellationToken cancellationToken = default)
    {
        List<Guid> accounts = [];
        if (erasure.Subject.AccountId is { } id)
        {
            accounts = await guardDb.RunAsync(db => db.Accounts.Where(a => a.Id == id || a.MergedIntoId == id).Select(a => a.Id).ToListAsync(cancellationToken),
                cancellationToken: cancellationToken);
            foreach (Guid account in accounts)
            {
                await sessions.EndEverywhereAsync(account, keepSession: null, keepAuthorization: null, "erased", cancellationToken);
                await DeleteSignInsAsync(account, cancellationToken);
            }
        }

        await guardDb.RunAsync(async db =>
        {
            Dictionary<Guid, string> usernameOf = await db.Accounts.Where(a => accounts.Contains(a.Id)).ToDictionaryAsync(a => a.Id, a => a.NormalizedUsername, cancellationToken);
            List<string> usernames = [.. usernameOf.Values];
            List<string> emails = [.. erasure.Subject.Emails.Select(e => e.ToLowerInvariant())];
            List<string> phones = [.. erasure.Subject.Phones];
            Dictionary<Guid, string> pseudonyms = accounts.Count > 0 ? await PseudonymsAsync(db, accounts, erasure.Pseudonym, cancellationToken) : [];
            string pseudonymUser = erasure.Subject.AccountId is { } main ? pseudonyms[main] : Usernames.ErasedOf(erasure.Pseudonym);
            await EraseLogAsync(db, erasure, accounts, usernameOf, emails, phones, pseudonyms, pseudonymUser, cancellationToken);

            await ForgetWaitingEventsAsync(db, accounts, cancellationToken);
            if (accounts.Count > 0)
            {
                await EraseAccountsAsync(db, erasure, accounts, usernames, pseudonyms, cancellationToken);
            }

            // A notice accepted by their address keeps that it was, and when, not by whom; the account's keeps the account.
            List<string> accepted = [.. emails, .. phones];
            await db.PrivacyAcceptances.Where(a => a.Address != null && accepted.Contains(a.Address))
                .ExecuteUpdateAsync(s => s.SetProperty(a => a.Address, (string?)null).SetProperty(a => a.Ip, (string?)null), cancellationToken);
            await db.PrivacyAcceptances.Where(a => a.AccountId != null && accounts.Contains(a.AccountId.Value))
                .ExecuteUpdateAsync(s => s.SetProperty(a => a.Ip, (string?)null), cancellationToken);

            // A released hold keeps why and when, not whom; an active one would have stopped the erasure.
            List<string> addresses = [.. emails, .. phones];
            await db.LegalHolds.Where(h => h.ReleasedAt != null && ((h.AccountId != null && accounts.Contains(h.AccountId.Value))
                    || (h.Address != null && addresses.Contains(h.Address))))
                .ExecuteUpdateAsync(s => s.SetProperty(h => h.Address, (string?)null), cancellationToken);
        }, requiresNew: true, cancellationToken, isTransactional: true);
    }

    /// <summary>
    /// Deletes the events about the accounts still waiting in Guard's outbox: one delivered after a store was erased (a
    /// name corrected, say) would put the person back in it. <see cref="PersonalDataErasures"/> runs this before any
    /// eraser, and Guard's own step again at the end. Every event that names an account is about that account alone.
    /// </summary>
    internal static async Task ForgetWaitingEventsAsync(GuardDbContext db, IEnumerable<Guid> accounts, CancellationToken ct)
    {
        if (db.Model.FindEntityType(typeof(Volo.Abp.EntityFrameworkCore.DistributedEvents.OutgoingEventRecord)) is not { } outbox)
        {
            return;
        }

        string table = $"\"{outbox.GetSchema()}\".\"{outbox.GetTableName()}\"";
        string sql = $"DELETE FROM {table} WHERE position(convert_to({{0}}, 'UTF8') in \"EventData\") > 0";
        foreach (Guid account in accounts)
        {
            await db.Database.ExecuteSqlRawAsync(sql, [account.ToString()], ct);
        }
    }

    /// <summary>
    /// The pseudonym's username for each account: "former-person-{n}" for the account erased, "-2", "-3"… for those
    /// merged into it, passing over any a directory happens to use (people can't choose one, <see cref="Usernames"/>).
    /// </summary>
    private static async Task<Dictionary<Guid, string>> PseudonymsAsync(GuardDbContext db, List<Guid> accounts, string pseudonym, CancellationToken ct)
    {
        string stem = Usernames.ErasedOf(pseudonym);
        string normalizedStem = GuardConstants.Normalize(stem);
        HashSet<string> taken = [.. await db.Accounts.Where(a => !accounts.Contains(a.Id) && a.NormalizedUsername.StartsWith(normalizedStem))
            .Select(a => a.NormalizedUsername).ToListAsync(ct)];
        List<Guid> ordered = await db.Accounts.Where(a => accounts.Contains(a.Id)).OrderBy(a => a.MergedIntoId != null).ThenBy(a => a.CreatedAt)
            .Select(a => a.Id).ToListAsync(ct);
        Dictionary<Guid, string> names = [];
        int next = 1;
        foreach (Guid account in ordered)
        {
            string name;
            do
            {
                name = next == 1 ? stem : $"{stem}-{next}";
                next++;
            }
            while (taken.Contains(GuardConstants.Normalize(name)));
            names[account] = name;
        }

        return names;
    }

    /// <summary>
    /// The security log keeps what happened. In the person's own entries (theirs, about them, made while acting as them,
    /// or under a username or address of theirs), their usernames and addresses become the pseudonym, and so does any
    /// value of an entry's detail that is wholly one of their names or addresses; a value that merely contains one is
    /// left, as it may be someone else's ("Ali" in "Alice"). Other people's entries aren't read.
    /// </summary>
    private static async Task EraseLogAsync(GuardDbContext db, PersonalDataErasure erasure, List<Guid> accounts, Dictionary<Guid, string> usernameOf,
        List<string> emails, List<string> phones, Dictionary<Guid, string> pseudonyms, string pseudonymUser, CancellationToken ct)
    {
        List<string> usernames = [.. usernameOf.Values];
        List<string> typed = [.. usernames, .. emails];
        List<string> named = [.. typed, .. phones];
        IQueryable<SecurityEvent> theirs = db.SecurityEvents.Where(e => (e.AccountId != null && accounts.Contains(e.AccountId.Value))
            || (e.TargetId != null && accounts.Contains(e.TargetId.Value))
            || (e.ActingAccountId != null && accounts.Contains(e.ActingAccountId.Value))
            || (e.Username != null && typed.Contains(e.Username.ToLower()))
            || (e.TargetId == null && e.TargetName != null && named.Contains(e.TargetName.ToLower())));

        // A rename's entry held the names before it, which the erasure doesn't know: it keeps that it happened.
        await theirs.Where(e => e.Type == SecurityAuditTypes.AccountRenamed).ExecuteUpdateAsync(s => s.SetProperty(e => e.Detail, (string?)null), ct);
        HashSet<string> identifiers = new([.. erasure.Names, .. usernames, .. emails, .. phones], StringComparer.OrdinalIgnoreCase);
        foreach (var row in await theirs.Where(e => e.Detail != null).Select(e => new { e.Id, e.Detail }).ToListAsync(ct))
        {
            if (Pseudonymised(row.Detail!, identifiers, erasure.Pseudonym) is { } detail)
            {
                await db.SecurityEvents.Where(e => e.Id == row.Id).ExecuteUpdateAsync(s => s.SetProperty(e => e.Detail, detail), ct);
            }
        }

        // A merge's entry says which account went into which, in words: each of theirs reads its pseudonym's username.
        Dictionary<string, string> renamed = pseudonyms.ToDictionary(p => usernameOf[p.Key], p => p.Value, StringComparer.OrdinalIgnoreCase);
        foreach (var row in await theirs.Where(e => e.Type == MergedType && e.Detail != null).Select(e => new { e.Id, e.Detail }).ToListAsync(ct))
        {
            if (Merged(row.Detail!, renamed) is { } detail)
            {
                await db.SecurityEvents.Where(e => e.Id == row.Id).ExecuteUpdateAsync(s => s.SetProperty(e => e.Detail, detail), ct);
            }
        }

        // Each account is named as the log names accounts, by its own username: the pseudonym's now, "-2", "-3"… for those
        // merged into the one erased. A username or address typed with no account of its own (a failed sign-in by an
        // address) reads the erased account's; an entry about an address of theirs, the pseudonym.
        foreach ((Guid account, string name) in pseudonyms)
        {
            string username = usernameOf[account];
            await theirs.Where(e => e.AccountId == account || (e.Username != null && e.Username.ToLower() == username))
                .ExecuteUpdateAsync(s => s.SetProperty(e => e.Username, name), ct);
            await theirs.Where(e => e.TargetId == account).ExecuteUpdateAsync(s => s.SetProperty(e => e.TargetName, name), ct);
        }

        await theirs.Where(e => e.Username != null && typed.Contains(e.Username.ToLower()))
            .ExecuteUpdateAsync(s => s.SetProperty(e => e.Username, pseudonymUser), ct);
        await theirs.Where(e => e.TargetId == null && e.TargetName != null && named.Contains(e.TargetName.ToLower()))
            .ExecuteUpdateAsync(s => s.SetProperty(e => e.TargetName, erasure.Pseudonym), ct);
    }

    /// <summary>The type of a merge's entries (<see cref="AccountMerges"/>).</summary>
    private const string MergedType = "account.merged";

    /// <summary>
    /// A merge's detail ("rita-old merged into rita", maybe "automatically (…)" after) with each username renamed to its
    /// pseudonym's; another person's stays. Null when neither is.
    /// </summary>
    internal static string? Merged(string detail, IReadOnlyDictionary<string, string> renamed)
    {
        const string into = " merged into ", automatically = " automatically (";
        int at = detail.IndexOf(into, StringComparison.Ordinal);
        if (at < 0)
        {
            return null;
        }

        string source = detail[..at], rest = detail[(at + into.Length)..];
        int end = rest.IndexOf(automatically, StringComparison.Ordinal);
        string survivor = end < 0 ? rest : rest[..end];
        string tail = end < 0 ? "" : rest[end..];
        string s = renamed.GetValueOrDefault(source, source), v = renamed.GetValueOrDefault(survivor, survivor);
        return s == source && v == survivor ? null : $"{s}{into}{v}{tail}";
    }

    /// <summary>An entry's detail with every value that is wholly one of the identifiers replaced; null when none is.</summary>
    internal static string? Pseudonymised(string detail, IReadOnlySet<string> identifiers, string pseudonym)
    {
        JsonNode? root;
        try
        {
            root = JsonNode.Parse(detail);
        }
        catch (JsonException)
        {
            return identifiers.Contains(detail.Trim()) ? pseudonym : null;
        }

        bool changed = false;
        JsonNode? Walk(JsonNode? node)
        {
            switch (node)
            {
                case JsonObject o:
                    foreach (string key in o.Select(p => p.Key).ToList())
                    {
                        JsonNode? child = o[key];
                        o.Remove(key);
                        o[key] = Walk(child);
                    }

                    return o;
                case JsonArray a:
                    List<JsonNode?> items = [.. a];
                    a.Clear();
                    items.ForEach(i => a.Add(Walk(i)));
                    return a;
                case JsonValue v when v.TryGetValue(out string? text) && identifiers.Contains(text.Trim()):
                    changed = true;
                    return JsonValue.Create(pseudonym);
                default:
                    return node;
            }
        }

        JsonNode? result = Walk(root);
        return changed ? result?.ToJsonString() ?? pseudonym : null;
    }

    private static async Task EraseAccountsAsync(GuardDbContext db, PersonalDataErasure erasure, List<Guid> accounts, List<string> usernames,
        Dictionary<Guid, string> pseudonyms, CancellationToken ct)
    {
        List<Guid> records = await db.DirectoryUsers.Where(u => usernames.Contains(u.NormalizedUsername)).Select(u => u.Id).ToListAsync(ct);
        await db.Memberships.Where(m => (m.MemberType == MemberType.Account && accounts.Contains(m.MemberId))
            || (m.MemberType == MemberType.DirectoryUser && records.Contains(m.MemberId))).ExecuteDeleteAsync(ct);
        await db.RoleGrants.Where(g => g.PrincipalType == PrincipalType.Account && accounts.Contains(g.PrincipalId)).ExecuteDeleteAsync(ct);
        await db.PersonalAccessTokens.Where(t => accounts.Contains(t.AccountId)).ExecuteDeleteAsync(ct);
        await db.SecondFactors.Where(f => accounts.Contains(f.AccountId)).ExecuteDeleteAsync(ct);
        await db.RecoveryCodes.Where(c => accounts.Contains(c.AccountId)).ExecuteDeleteAsync(ct);
        await db.SentCodes.Where(c => accounts.Contains(c.AccountId)).ExecuteDeleteAsync(ct);
        await db.SignInTickets.Where(t => accounts.Contains(t.AccountId)).ExecuteDeleteAsync(ct);
        await db.SessionHandoffs.Where(h => accounts.Contains(h.AccountId)).ExecuteDeleteAsync(ct);
        await db.WebSessions.Where(s => accounts.Contains(s.AccountId)).ExecuteDeleteAsync(ct);
        await db.AccountEmails.Where(e => accounts.Contains(e.AccountId)).ExecuteDeleteAsync(ct);
        await db.DirectoryUsers.Where(u => records.Contains(u.Id)).ExecuteDeleteAsync(ct);

        // Merge records keep that two accounts became one, not who they were.
        foreach ((Guid account, string username) in pseudonyms)
        {
            await db.Merges.Where(m => m.SourceId == account).ExecuteUpdateAsync(s => s
                .SetProperty(m => m.SourceUsername, username)
                .SetProperty(m => m.SourceDisplayName, erasure.Pseudonym)
                .SetProperty(m => m.SourceEmail, (string?)null), ct);
            await db.Merges.Where(m => m.SurvivorId == account).ExecuteUpdateAsync(s => s.SetProperty(m => m.SurvivorUsername, username), ct);
        }

        // The account itself: its pseudonym, no address, inactive for good.
        DateTime now = DateTime.UtcNow;
        foreach (Account account in await db.Accounts.Where(a => accounts.Contains(a.Id)).ToListAsync(ct))
        {
            account.ChangeUsername(pseudonyms[account.Id]);
            account.DisplayName = erasure.Pseudonym;
            account.SetDisplayNames(null); // the name in every language goes with it
            (account.Email, account.MailTo, account.DirectoryUserId) = (null, null, null);
            (account.Status, account.StatusReason, account.LockedLocally, account.ErasedAt) = (AccountStatus.Inactive, ErasedReason, true, now);
            (account.Language, account.TimeZone, account.Motion, account.LastLoginAt) = (null, null, null, null);
        }

        await db.SaveChangesAsync(ct);
    }

    /// <summary>The phone app's and other apps' sign-ins, and the permissions people gave apps: ended above, removed here.</summary>
    private async Task DeleteSignInsAsync(Guid account, CancellationToken ct)
    {
        string subject = account.ToString();
        List<object> found = [];
        await foreach (object token in tokens.FindBySubjectAsync(subject, ct))
        {
            found.Add(token);
        }

        foreach (object token in found)
        {
            await tokens.DeleteAsync(token, ct);
        }

        found.Clear();
        await foreach (object authorization in authorizations.FindBySubjectAsync(subject, ct))
        {
            found.Add(authorization);
        }

        foreach (object authorization in found)
        {
            await authorizations.DeleteAsync(authorization, ct);
        }
    }
}
