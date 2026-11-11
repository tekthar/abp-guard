using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using AbpGuard.Data;
using AbpGuard.Domain;
using Volo.Abp;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services.Privacy;

public sealed record LegalHoldInput(Guid? AccountId, string? Email, string? Phone, string Reason, DateTime? Until);

public sealed record LegalHoldDto(Guid Id, Guid? AccountId, string? Username, string? Address, string Reason, DateTime? Until, DateTime CreatedAt,
    DateTime? ReleasedAt, bool Active);

public sealed record ErasureRequestInput(string? Reason);

public sealed record ErasureDeclineInput(string Reason);

public sealed record OutsideErasureInput(string? Email, string? Phone);

/// <summary>An erasure as admins see it: whom (while it isn't done), its state, and each store's outcome.</summary>
public sealed record ErasureDto(Guid Id, int Number, string Pseudonym, Guid? AccountId, string? About, string State, string? Reason, string? DeclinedReason,
    DateTime CreatedAt, DateTime? FinishedAt, IReadOnlyDictionary<string, string> Stores);

/// <summary>What an erasure would do: the stores it goes through, the holds that stop it, the accounts merged into this one.</summary>
public sealed record ErasurePreviewDto(string About, IReadOnlyList<string> Stores, IReadOnlyList<LegalHoldDto> Holds, IReadOnlyList<string> Merged, string? Directory);

/// <summary>
/// Erasing a person (PDPL's right to destruction). An account becomes "Former person {n}": every module's
/// and plugin's eraser (<see cref="IPersonalDataEraser"/>) runs first, with the person's identifiers, and Guard's own
/// last, only once all have succeeded; a store that fails leaves the erasure running, to be resumed, so no identifier is
/// lost before every store is done. A legal hold on the person stops it. A person may ask; an admin erases or declines.
/// </summary>
public sealed class PersonalDataErasures(PersonalDataCatalog catalog, IGuardExtensions extensions, IServiceProvider services, GuardDb guardDb,
    PersonalDataExports exports, IGuardLocks locks, ILogger<PersonalDataErasures> logger) : ITransientDependency
{
    public const string Done = "done";

    /// <summary>Erased by an eraser that names it, though its module or plugin doesn't declare it (the data map misses it).</summary>
    public const string DoneUndeclared = "done, though its module or plugin doesn't declare this store";

    /// <summary>An outcome that doesn't hold the erasure back: nothing here can erase it, and waiting won't change that.</summary>
    public const string NothingErases = "nothing erases this store";

    public const string PluginOff = "its plugin is off: resume once it's on";

    /// <summary>An uninstalled plugin's store: what it kept remains, and Guard's last step would leave it unfindable.</summary>
    public const string PluginUninstalled = "its plugin is uninstalled, and what it kept remains: reinstall it and resume, or erase without this store";

    /// <summary>A plugin enabled but held back (a safe mode, or it failed to load): it leases nothing, so its stores wait.</summary>
    public const string PluginNotRunning = "its plugin isn't running (safe mode, or it failed to load): resume once it is";

    /// <summary>An admin erased without this store, with why ("skipped by {admin}: {reason}"): it holds the erasure no more.</summary>
    public const string SkippedPrefix = "skipped by ";

    public const string StillRunningCode = "still_running";
    public const string PluginsHeldCode = "plugins_held";

    /// <summary>How long one eraser may take before its stores are marked failed, to resume (a plugin's that hangs holds nothing else).</summary>
    public static readonly TimeSpan EraserTimeLimit = TimeSpan.FromMinutes(5);
    public const string HeldCode = "legal_hold";
    public const string DirectoryOwnedCode = "directory_owned";

    /// <summary>The subject as kept while an erasure runs.</summary>
    private sealed record Subject(Guid? AccountId, List<string> Emails, List<string> Phones, List<string> Names, List<Guid> Merged, string About);

    public static string PseudonymOf(int number) => $"Former person {number}";

    public static string UsernameOf(int number) => $"former-person-{number}";

    // ---- legal holds ----

    public Task<List<LegalHoldDto>> HoldsAsync(CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        List<LegalHold> holds = await db.LegalHolds.AsNoTracking().OrderByDescending(h => h.CreatedAt).Take(500).ToListAsync(ct);
        List<Guid> ids = [.. holds.Where(h => h.AccountId is not null).Select(h => h.AccountId!.Value)];
        Dictionary<Guid, string> names = await db.Accounts.AsNoTracking().Where(a => ids.Contains(a.Id)).ToDictionaryAsync(a => a.Id, a => a.Username, ct);
        return holds.Select(h => Dto(h, names)).ToList();
    }, cancellationToken: ct);

    public async Task<LegalHoldDto> HoldAsync(LegalHoldInput input, Guid actor, CancellationToken ct)
    {
        string reason = (input.Reason ?? "").Trim();
        if (reason.Length is 0 or > 1000)
        {
            throw new UserFriendlyException("Say why the data must be kept (the law or the case), in at most 1000 characters.");
        }

        PersonalDataSubject outside = PersonalDataSubject.Outside(input.Email, input.Phone);
        string? address = input.AccountId is null ? outside.Emails.Concat(outside.Phones).FirstOrDefault() : null;
        if (input.AccountId is null && address is null)
        {
            throw new UserFriendlyException("Hold an account, or someone outside by their email address or phone number.", "no_address");
        }

        return await guardDb.RunAsync(async db =>
        {
            if (input.AccountId is { } id && !await db.Accounts.AnyAsync(a => a.Id == id, ct))
            {
                throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(Account), id);
            }

            LegalHold hold = db.LegalHolds.Add(new LegalHold(Guid.NewGuid(), input.AccountId, address, reason, input.Until, actor)).Entity;
            await db.SaveChangesAsync(ct);
            Dictionary<Guid, string> names = input.AccountId is { } a
                ? await db.Accounts.AsNoTracking().Where(x => x.Id == a).ToDictionaryAsync(x => x.Id, x => x.Username, ct)
                : [];
            return Dto(hold, names);
        }, requiresNew: true, ct);
    }

    public Task<LegalHoldDto> ReleaseAsync(Guid id, Guid actor, CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        LegalHold hold = await db.LegalHolds.FirstOrDefaultAsync(h => h.Id == id, ct) ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(LegalHold), id);
        (hold.ReleasedAt, hold.ReleasedBy) = (hold.ReleasedAt ?? DateTime.UtcNow, hold.ReleasedBy ?? actor);
        await db.SaveChangesAsync(ct);
        return Dto(hold, new Dictionary<Guid, string>());
    }, requiresNew: true, ct);

    private static LegalHoldDto Dto(LegalHold h, IReadOnlyDictionary<Guid, string> names) =>
        new(h.Id, h.AccountId, h.AccountId is { } id ? names.GetValueOrDefault(id) : null, h.Address, h.Reason, h.Until, h.CreatedAt, h.ReleasedAt, h.ActiveAt(DateTime.UtcNow));

    /// <summary>
    /// A directory that syncs and still has the account, or one merged into it: erasing frees the username, so its next
    /// sync would bring the person back, by name, as a new account. They're removed there first. A record still there is
    /// active, or was seen by the directory's last sync that succeeded (disabled there, not gone); one a sync marked
    /// missing doesn't hold the erasure, nor does the internal directory or an "Imported from …" one, which never sync.
    /// </summary>
    private static async Task<string?> DirectoryStillHoldingAsync(GuardDbContext db, Subject subject, CancellationToken ct)
    {
        List<Guid> accounts = [.. new[] { subject.AccountId }.OfType<Guid>().Concat(subject.Merged)];
        if (accounts.Count == 0)
        {
            return null;
        }

        List<string> usernames = await db.Accounts.AsNoTracking().Where(a => accounts.Contains(a.Id)).Select(a => a.NormalizedUsername).ToListAsync(ct);
        var records = await db.DirectoryUsers.AsNoTracking().Where(u => usernames.Contains(u.NormalizedUsername))
            .Join(db.Directories.AsNoTracking().Where(d => d.Type != GuardConstants.InternalType && d.Type != AccountProvisioning.ImportedType),
                u => u.DirectoryId, d => d.Id, (u, d) => new { u.DirectoryId, u.IsActive, u.LastSyncedAt, d.Name })
            .ToListAsync(ct);
        foreach (var record in records.OrderByDescending(r => r.IsActive))
        {
            if (record.IsActive)
            {
                return record.Name;
            }

            DateTime? lastSync = await db.SyncRuns.AsNoTracking().Where(r => r.DirectoryId == record.DirectoryId && r.Succeeded == true)
                .OrderByDescending(r => r.StartedAt).Select(r => (DateTime?)r.StartedAt).FirstOrDefaultAsync(ct);
            if (record.LastSyncedAt is { } seen && (lastSync is null || seen >= lastSync))
            {
                return record.Name;
            }
        }

        return null;
    }

    private static Task<List<LegalHold>> ActiveHoldsAsync(GuardDbContext db, Subject subject, CancellationToken ct)
    {
        DateTime now = DateTime.UtcNow;
        List<Guid> accounts = [.. new[] { subject.AccountId }.OfType<Guid>().Concat(subject.Merged)];
        List<string> addresses = [.. subject.Emails.Select(e => e.ToLowerInvariant()), .. subject.Phones];
        return db.LegalHolds.Where(h => h.ReleasedAt == null && (h.Until == null || h.Until > now)
            && ((h.AccountId != null && accounts.Contains(h.AccountId.Value)) || (h.Address != null && addresses.Contains(h.Address)))).ToListAsync(ct);
    }

    // ---- requests, previews, erasures ----

    /// <summary>A person asks to be erased: one open request at a time, waiting for an admin.</summary>
    public Task<ErasureDto> RequestAsync(Guid accountId, string? reason, CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        Account account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, ct)
            ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(Account), accountId);
        if (account.IsService)
        {
            throw new UserFriendlyException("A service account has no data of its own to erase.", "not_a_person");
        }

        PersonalDataErasureRecord? open = await db.Erasures.FirstOrDefaultAsync(e => e.AccountId == accountId
            && (e.State == ErasureStates.Requested || e.State == ErasureStates.Running), ct);
        if (open is null)
        {
            string? words = reason?.Trim();
            open = db.Erasures.Add(new PersonalDataErasureRecord(Guid.NewGuid(), accountId, null, ErasureStates.Requested)
            {
                Reason = string.IsNullOrEmpty(words) ? null : words[..Math.Min(words.Length, 2000)],
                RequestedBy = accountId,
            }).Entity;
            await db.SaveChangesAsync(ct);
        }

        return Dto(open, account.Username);
    }, requiresNew: true, ct);

    /// <summary>The person's latest request, for the You page: waiting, declined (with why) or running.</summary>
    public Task<ErasureDto?> LatestOfAsync(Guid accountId, CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        PersonalDataErasureRecord? latest = await db.Erasures.AsNoTracking().Where(e => e.AccountId == accountId && e.RequestedBy == accountId)
            .OrderByDescending(e => e.CreatedAt).FirstOrDefaultAsync(ct);
        return latest is null ? null : Dto(latest, null);
    }, cancellationToken: ct);

    public Task<List<ErasureDto>> ListAsync(CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        List<PersonalDataErasureRecord> rows = await db.Erasures.AsNoTracking().OrderByDescending(e => e.CreatedAt).Take(200).ToListAsync(ct);
        List<Guid> ids = [.. rows.Where(r => r.AccountId is not null && r.State != ErasureStates.Done).Select(r => r.AccountId!.Value)];
        Dictionary<Guid, string> names = await db.Accounts.AsNoTracking().Where(a => ids.Contains(a.Id)).ToDictionaryAsync(a => a.Id, a => a.Username, ct);
        return rows.Select(r => Dto(r, r.AccountId is { } id ? names.GetValueOrDefault(id) : null)).ToList();
    }, cancellationToken: ct);

    public async Task<ErasurePreviewDto> PreviewAccountAsync(Guid accountId, CancellationToken ct)
    {
        Subject subject = await SubjectOfAccountAsync(accountId, ct);
        return await PreviewAsync(subject, ct);
    }

    public Task<ErasurePreviewDto> PreviewOutsideAsync(PersonalDataSubject outside, CancellationToken ct) =>
        PreviewAsync(OutsideSubject(outside), ct);

    private async Task<ErasurePreviewDto> PreviewAsync(Subject subject, CancellationToken ct)
    {
        PrivacyMapDto map = await catalog.MapAsync(ct);
        return await guardDb.RunAsync(async db =>
        {
            List<LegalHold> holds = await ActiveHoldsAsync(db, subject, ct);
            List<string> merged = await db.Accounts.AsNoTracking().Where(a => subject.Merged.Contains(a.Id)).Select(a => a.Username).ToListAsync(ct);
            string? directory = await DirectoryStillHoldingAsync(db, subject, ct);
            return new ErasurePreviewDto(subject.About, [.. map.Stores.Select(s => s.Key)], [.. holds.Select(h => Dto(h, new Dictionary<Guid, string>()))], merged, directory);
        }, cancellationToken: ct);
    }

    /// <summary>An admin erases an account (and any request it made becomes this erasure). Refused while a legal hold is on.</summary>
    public async Task<ErasureDto> EraseAccountAsync(Guid accountId, Guid actor, CancellationToken ct)
    {
        RefuseWhilePluginsHeld();
        Subject subject = await SubjectOfAccountAsync(accountId, ct);
        Guid id = await guardDb.RunAsync(async db =>
        {
            if ((await ActiveHoldsAsync(db, subject, ct)).Count > 0)
            {
                throw new UserFriendlyException("A legal hold is on this person: release it before erasing them.", HeldCode);
            }

            if (await DirectoryStillHoldingAsync(db, subject, ct) is { } directory)
            {
                throw new UserFriendlyException(
                    $"{directory} still has this person, so its next sync would bring them back by name: remove them from {directory} first.",
                    DirectoryOwnedCode);
            }

            PersonalDataErasureRecord record = await db.Erasures.FirstOrDefaultAsync(e => e.AccountId == accountId
                && (e.State == ErasureStates.Requested || e.State == ErasureStates.Running), ct)
                ?? db.Erasures.Add(new PersonalDataErasureRecord(Guid.NewGuid(), accountId, null, ErasureStates.Running)).Entity;
            Start(record, subject, actor);
            await db.SaveChangesAsync(ct);
            return record.Id;
        }, requiresNew: true, ct, isTransactional: true);
        return await RunAsync(id, ct);
    }

    /// <summary>An admin erases someone outside, by an address.</summary>
    public async Task<ErasureDto> EraseOutsideAsync(PersonalDataSubject outside, Guid actor, CancellationToken ct)
    {
        if (outside.Emails.Count + outside.Phones.Count == 0)
        {
            throw new UserFriendlyException("Give the person's email address or phone number.", "no_address");
        }

        RefuseWhilePluginsHeld();
        Subject subject = OutsideSubject(outside);
        Guid id = await guardDb.RunAsync(async db =>
        {
            if ((await ActiveHoldsAsync(db, subject, ct)).Count > 0)
            {
                throw new UserFriendlyException("A legal hold is on this address: release it before erasing.", HeldCode);
            }

            PersonalDataErasureRecord record = db.Erasures.Add(new PersonalDataErasureRecord(Guid.NewGuid(), null, null, ErasureStates.Running)).Entity;
            Start(record, subject, actor);
            await db.SaveChangesAsync(ct);
            return record.Id;
        }, requiresNew: true, ct, isTransactional: true);
        return await RunAsync(id, ct);
    }

    /// <summary>Runs the stores an erasure hasn't finished: after one failed, or a plugin was off.</summary>
    public Task<ErasureDto> ResumeAsync(Guid id, CancellationToken ct)
    {
        RefuseWhilePluginsHeld();
        return RunAsync(id, ct);
    }

    /// <summary>
    /// An admin finishes an erasure without one plugin's store that's waiting (its plugin off, uninstalled or not
    /// running), saying why: the outcome keeps who and why, and the erasure runs on. Guard's and the modules' stores
    /// can't be left out: a failed one is resumed once what failed is fixed.
    /// </summary>
    public async Task<ErasureDto> SkipStoreAsync(Guid id, string store, Guid actor, string reason, CancellationToken ct)
    {
        string why = (reason ?? "").Trim();
        if (why.Length is 0 or > 1000)
        {
            throw new UserFriendlyException("Say why the erasure goes on without this store, in at most 1000 characters.", "no_reason");
        }

        PrivacyMapDto map = await catalog.MapAsync(ct);
        if (!map.Stores.Any(s => s.Key == store && s.OwnerKind == PrivacyStoreDto.Plugin))
        {
            throw new UserFriendlyException("Only a plugin's store can be left out of an erasure.", "not_a_plugin_store");
        }

        await using (await TakeAsync(id, ct))
        {
            await guardDb.RunAsync(async db =>
            {
                PersonalDataErasureRecord record = await db.Erasures.FirstOrDefaultAsync(e => e.Id == id, ct)
                    ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(PersonalDataErasureRecord), id);
                Dictionary<string, string> outcome = JsonSerializer.Deserialize<Dictionary<string, string>>(record.Stores) ?? [];
                if (record.State != ErasureStates.Running || !outcome.TryGetValue(store, out string? now) || Settled(now)
                    || now.StartsWith(NothingErases, StringComparison.Ordinal))
                {
                    throw new UserFriendlyException("Only a store this erasure is waiting for can be left out.", "not_waiting");
                }

                string admin = await db.Accounts.AsNoTracking().Where(a => a.Id == actor).Select(a => a.Username).FirstOrDefaultAsync(ct) ?? actor.ToString();
                outcome[store] = $"{SkippedPrefix}{admin}: {why}";
                record.Stores = JsonSerializer.Serialize(outcome);
                await db.SaveChangesAsync(ct);
            }, requiresNew: true, ct);
        }

        return await RunAsync(id, ct);
    }

    /// <summary>
    /// The outcome of a plugin's store no eraser took: one of only fields on the host's records and assets is done with
    /// the host's stores (or waits for those that failed, by name); another waits while its plugin is off, uninstalled
    /// (what it kept remains) or enabled but not running. One whose plugin runs and erases nothing of it is reported.
    /// </summary>
    public static string Untaken(bool onlyFields, string? pluginState, bool running, IReadOnlyCollection<string> failedModules) =>
        onlyFields
            ? failedModules.Count > 0 ? $"its fields are on stores that failed ({string.Join(", ", failedModules)}): resume once they're done" : Done
            : pluginState switch
            {
                InstalledPlugin.States.Disabled => PluginOff,
                InstalledPlugin.States.Removed => PluginUninstalled,
                InstalledPlugin.States.Enabled when !running => PluginNotRunning,
                _ => NothingErases,
            };

    /// <summary>Done, or left out by an admin: a store that holds the erasure no more, and isn't run again.</summary>
    public static bool Settled(string? outcome) =>
        outcome is Done or DoneUndeclared || outcome?.StartsWith(SkippedPrefix, StringComparison.Ordinal) == true;

    private void RefuseWhilePluginsHeld()
    {
        if (extensions.PluginsHeldBecause is { } why)
        {
            throw new UserFriendlyException($"{why}: no erasure starts or resumes until the plugins run, so none finishes without their data.",
                PluginsHeldCode);
        }
    }

    /// <summary>
    /// One run of an erasure at a time, on every server: an eraser that hasn't returned yet (one that doesn't honour its
    /// token) would otherwise run again beside a resume.
    /// </summary>
    private async Task<IAsyncDisposable> TakeAsync(Guid id, CancellationToken ct) =>
        await locks.TryTakeAsync($"erasure:{id}", ct)
        ?? throw new UserFriendlyException("This erasure is still running: wait for it to finish, then look again.", StillRunningCode);

    public Task<ErasureDto> DeclineAsync(Guid id, Guid actor, string reason, CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        PersonalDataErasureRecord record = await db.Erasures.FirstOrDefaultAsync(e => e.Id == id, ct)
            ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(PersonalDataErasureRecord), id);
        if (record.State != ErasureStates.Requested)
        {
            throw new UserFriendlyException("Only a request that's waiting can be declined.");
        }

        (record.State, record.DeclinedReason, record.DecidedBy) = (ErasureStates.Declined, (reason ?? "").Trim(), actor);
        await db.SaveChangesAsync(ct);
        string? username = record.AccountId is { } a ? await db.Accounts.AsNoTracking().Where(x => x.Id == a).Select(x => x.Username).FirstOrDefaultAsync(ct) : null;
        return Dto(record, username);
    }, requiresNew: true, ct);

    private static void Start(PersonalDataErasureRecord record, Subject subject, Guid actor)
    {
        record.Subject = JsonSerializer.Serialize(subject);
        record.State = ErasureStates.Running;
        record.DecidedBy = actor;
        record.StartedAt ??= DateTime.UtcNow;
    }

    private async Task<ErasureDto> RunAsync(Guid id, CancellationToken ct)
    {
        await using IAsyncDisposable taken = await TakeAsync(id, ct);
        (PersonalDataErasureRecord record, Subject subject) = await guardDb.RunAsync(async db =>
        {
            PersonalDataErasureRecord r = await db.Erasures.AsNoTracking().FirstOrDefaultAsync(e => e.Id == id, ct)
                ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(PersonalDataErasureRecord), id);
            if (r.State != ErasureStates.Running || r.Subject is null)
            {
                throw new UserFriendlyException("This erasure isn't running.");
            }

            return (r, JsonSerializer.Deserialize<Subject>(r.Subject)!);
        }, cancellationToken: ct);

        Dictionary<string, string> outcome = JsonSerializer.Deserialize<Dictionary<string, string>>(record.Stores) ?? [];
        PersonalDataErasure erasure = new(new PersonalDataSubject(subject.AccountId, subject.Emails, subject.Phones), subject.Names, PseudonymOf(record.Number));
        PrivacyMapDto map = await catalog.MapAsync(ct);

        // Events about them waiting to go are dropped first, so none brings a name back to a store already erased.
        List<Guid> accounts = [.. new[] { subject.AccountId }.OfType<Guid>().Concat(subject.Merged)];
        await guardDb.RunAsync(db => GuardPersonalDataEraser.ForgetWaitingEventsAsync(db, accounts, ct), requiresNew: true, ct);

        HashSet<string> attempted = [];

        // Every module's and plugin's eraser first, Guard's own last: it removes what finds the person.
        List<IPersonalDataEraser> host = [.. services.GetServices<IPersonalDataEraser>()];
        HashSet<string> modules = [.. map.Stores.Where(s => s.OwnerKind == PrivacyStoreDto.Module).Select(s => s.Key)];
        foreach (IPersonalDataEraser eraser in host.Where(e => e is not GuardPersonalDataEraser))
        {
            await RunOneAsync(eraser, null, modules);
        }

        // Every plugin that declares a store, whether it's on or not (a lease holds only those on), and any with an eraser.
        List<string> modulesFailed = [.. modules.Where(s => outcome.TryGetValue(s, out string? v) && v != Done).Order(StringComparer.Ordinal)];
        List<string> plugins;
        await using (IGuardLease<IPersonalDataEraser> lease = extensions.Lease<IPersonalDataEraser>(services))
        {
            plugins = [.. lease.Items.Where(i => i.PluginKey is not null).Select(i => i.PluginKey!)
                .Concat(map.Stores.Where(s => s.OwnerKind == PrivacyStoreDto.Plugin).Select(s => s.Owner)).Distinct(StringComparer.Ordinal)];
        }

        Dictionary<string, string> states = map.Plugins.ToDictionary(p => p.Key, p => p.State, StringComparer.Ordinal);
        foreach (string plugin in plugins)
        {
            List<PrivacyStoreDto> stores = [.. map.Stores.Where(s => s.OwnerKind == PrivacyStoreDto.Plugin && s.Owner == plugin)];
            HashSet<string> declared = [.. stores.Select(s => s.Key)];
            await using (IGuardLease<IPersonalDataEraser> lease = extensions.Lease<IPersonalDataEraser>(services))
            {
                foreach (IPersonalDataEraser eraser in lease.Items.Where(i => i.PluginKey == plugin).Select(i => i.Instance))
                {
                    await RunOneAsync(eraser, plugin, declared);
                }
            }

            // A store no eraser of the plugin took this time: its fields are the host's, or the plugin is off, or has none.
            foreach (PrivacyStoreDto store in stores.Where(s => !Settled(outcome.GetValueOrDefault(s.Key)) && !attempted.Contains(s.Key)))
            {
                outcome[store.Key] = Untaken(store.Tables.Count == 0 && store.Files.Count == 0 && store.Fields.Count > 0, states.GetValueOrDefault(plugin),
                    extensions.IsRunning(plugin), modulesFailed);
            }
        }

        foreach (PrivacyStoreDto store in map.Stores.Where(s => !outcome.ContainsKey(s.Key)))
        {
            outcome[store.Key] = NothingErases;
        }

        bool failed = outcome.Values.Any(v => !Settled(v) && !v.StartsWith(NothingErases, StringComparison.Ordinal));
        if (!failed && host.OfType<GuardPersonalDataEraser>().FirstOrDefault() is { } guard)
        {
            await RunOneAsync(guard, null, modules);
            failed = guard.Stores.Any(s => outcome.GetValueOrDefault(s) != Done);
        }

        return await guardDb.RunAsync(async db =>
        {
            PersonalDataErasureRecord saved = await db.Erasures.FirstAsync(e => e.Id == id, ct);
            saved.Stores = JsonSerializer.Serialize(outcome);
            if (!failed)
            {
                (saved.State, saved.Subject, saved.FinishedAt) = (ErasureStates.Done, null, DateTime.UtcNow);
            }

            await db.SaveChangesAsync(ct);
            return Dto(saved, failed ? subject.About : null);
        }, requiresNew: true, ct);

        async Task RunOneAsync(IPersonalDataEraser eraser, string? plugin, HashSet<string> declared)
        {
            // A store the eraser names but its owner doesn't declare is erased all the same, and said so: the data map
            // misses it, which its publisher fixes, but the erasure isn't held for it.
            List<string> stores = [.. eraser.Stores.Select(named => plugin is null ? named : $"{plugin}.{named}").Where(key => !Settled(outcome.GetValueOrDefault(key)))];
            if (stores.Count == 0)
            {
                return;
            }

            attempted.UnionWith(stores);
            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
            limit.CancelAfter(EraserTimeLimit);
            try
            {
                await eraser.EraseAsync(erasure, limit.Token);
                stores.ForEach(s => outcome[s] = declared.Contains(s) ? Done : DoneUndeclared);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                logger.LogWarning("The erasure of {Stores} took longer than {Limit}", string.Join(", ", stores), EraserTimeLimit);
                stores.ForEach(s => outcome[s] = "took too long: resume it");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "The erasure of {Stores} failed", string.Join(", ", stores));
                stores.ForEach(s => outcome[s] = "failed; the site's log says why: resume it");
            }
        }
    }

    // ---- subjects ----

    /// <summary>An account's subject: every address it had, its names, and the accounts merged into it.</summary>
    private async Task<Subject> SubjectOfAccountAsync(Guid accountId, CancellationToken ct)
    {
        PersonalDataSubject account = await exports.SubjectOfAccountAsync(accountId, ct)
            ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(Account), accountId);
        return await guardDb.RunAsync(async db =>
        {
            Account a = await db.Accounts.AsNoTracking().FirstAsync(x => x.Id == accountId, ct);
            if (a.IsService || a.ErasedAt is not null)
            {
                throw new UserFriendlyException(a.IsService ? "A service account has no data of its own to erase." : "This account is erased already.", "not_a_person");
            }

            List<Account> merged = await db.Accounts.AsNoTracking().Where(x => x.MergedIntoId == accountId).ToListAsync(ct);
            List<string> mergedEmails = [.. merged.Where(m => m.Email is not null).Select(m => m.Email!)];
            List<string> names = [.. new[] { a.DisplayName, a.Username }.Concat(merged.SelectMany(m => new[] { m.DisplayName, m.Username }))
                .Where(n => !string.IsNullOrWhiteSpace(n)).Distinct(StringComparer.Ordinal)];
            return new Subject(accountId, [.. account.Emails.Concat(mergedEmails).Distinct(StringComparer.OrdinalIgnoreCase)], [], names,
                [.. merged.Select(m => m.Id)], $"{a.DisplayName} ({a.Username})");
        }, cancellationToken: ct);
    }

    private static Subject OutsideSubject(PersonalDataSubject outside) =>
        new(null, [.. outside.Emails], [.. outside.Phones], [], [], outside.Emails.Concat(outside.Phones).FirstOrDefault() ?? "");

    private static ErasureDto Dto(PersonalDataErasureRecord r, string? about) =>
        new(r.Id, r.Number, PseudonymOf(r.Number), r.AccountId, about, r.State, r.Reason, r.DeclinedReason, r.CreatedAt, r.FinishedAt,
            JsonSerializer.Deserialize<Dictionary<string, string>>(r.Stores) ?? []);
}
