using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AbpGuard.Data;
using AbpGuard.Directories;
using AbpGuard.Domain;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>
/// Full sync of one directory: users, groups and memberships are cached locally, users missing from the
/// source are deactivated (never deleted), sync only replaces its own "Directory" membership rows, and
/// "Manual" rows added in Guard are never touched. Then directory precedence is re-applied.
/// </summary>
public class DirectorySyncService(
    GuardDb guardDb,
    ConnectorCatalog connectors,
    AccountProjector projector,
    IGuardEventSink events,
    AccountMergeService merges,
    IGuardLocks clusterLocks,
    ILogger<DirectorySyncService> logger) : ITransientDependency
{
    private static readonly ConcurrentDictionary<Guid, SemaphoreSlim> Locks = new();

    public async Task<SyncRun> SyncAsync(Guid directoryId, CancellationToken cancellationToken = default)
    {
        SemaphoreSlim gate = Locks.GetOrAdd(directoryId, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        try
        {
            // And across servers (M10 step 2): a sync now waits for another server's sync of the same directory.
            await using IAsyncDisposable held = await clusterLocks.TakeAsync($"directory-sync:{directoryId}", cancellationToken);
            return await SyncCoreAsync(directoryId, cancellationToken);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<SyncRun> SyncCoreAsync(Guid directoryId, CancellationToken cancellationToken)
    {
        Stopwatch watch = Stopwatch.StartNew();
        List<object> pending = [];
        SyncRun run = new(Guid.NewGuid(), directoryId);
        string directoryName = directoryId.ToString();

        try
        {
            await guardDb.RunAsync(async db =>
            {
                UserDirectory directory = await db.Directories.FirstOrDefaultAsync(d => d.Id == directoryId, cancellationToken)
                    ?? throw new InvalidOperationException("Directory not found.");
                directoryName = directory.Name;
                db.SyncRuns.Add(run);

                if (!directory.IsInternal)
                {
                    (List<DirectoryUserRecord> users, List<DirectoryGroupRecord> groups) = await connectors.WithConnectorAsync(directory.Type, async (connector, _) =>
                    {
                        if (connector is null)
                        {
                            throw new InvalidOperationException($"No connector for directory type '{directory.Type}'. Is its plugin enabled?");
                        }

                        DirectoryConnectionContext context = connectors.BuildContext(directory);
                        List<DirectoryUserRecord> u = [];
                        await foreach (DirectoryUserRecord record in connector.ReadUsersAsync(context, cancellationToken))
                        {
                            u.Add(record);
                        }

                        List<DirectoryGroupRecord> g = [];
                        await foreach (DirectoryGroupRecord record in connector.ReadGroupsAsync(context, cancellationToken))
                        {
                            g.Add(record);
                        }

                        return (u, g);
                    });

                    int left = await ApplyUsersAsync(db, directory, users, run, cancellationToken);
                    if (left > 0)
                    {
                        logger.LogWarning("Sync of directory {Directory}: {Count} names by language had no valid language code and were left out", directoryName, left);
                    }

                    if (NoNamesFound(users))
                    {
                        logger.LogWarning("Sync of directory {Directory}: names by language are set up, but no one had any. Check that the account the directory is read with can read each language's attribute", directoryName);
                    }
                    await db.SaveChangesAsync(cancellationToken);
                    await ApplyGroupsAsync(db, directory, groups, run, cancellationToken);
                }

                await db.SaveChangesAsync(cancellationToken);
                pending.AddRange(await projector.RebuildAsync(db, cancellationToken: cancellationToken));

                run.Succeeded = true;
                run.FinishedAt = DateTime.UtcNow;
                directory.LastSyncAt = run.FinishedAt;
                directory.LastSyncSucceeded = true;
                directory.LastSyncMessage = $"{run.UsersAdded} added, {run.UsersUpdated} updated, {run.UsersDeactivated} deactivated, {run.GroupsSynced} groups";
                await db.SaveChangesAsync(cancellationToken);
                await Organizations.ApplyDomainsAsync(db, cancellationToken); // emails may have changed
                // In the sync's unit of work: its accounts' events commit with it.
                foreach (object e in pending)
                {
                    await PublishAsync(e, cancellationToken);
                }
            }, requiresNew: true, cancellationToken, isTransactional: true);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Sync of directory {Directory} failed", directoryName);
            run.Succeeded = false;
            run.FinishedAt = DateTime.UtcNow;
            run.Error = ex.Message;
            await guardDb.RunAsync(async db =>
            {
                UserDirectory? directory = await db.Directories.FirstOrDefaultAsync(d => d.Id == directoryId, cancellationToken);
                if (directory is not null)
                {
                    directory.LastSyncAt = run.FinishedAt;
                    directory.LastSyncSucceeded = false;
                    directory.LastSyncMessage = ex.Message;
                }

                SyncRun failed = new(run.Id, directoryId) { FinishedAt = run.FinishedAt, Succeeded = false, Error = ex.Message };
                db.SyncRuns.Add(failed);
                await db.SaveChangesAsync(cancellationToken);
            }, requiresNew: true, cancellationToken);
        }

        if (run.Succeeded == true)
        {
            // Someone a placeholder stood for may have arrived with this sync.
            await merges.FoldPlaceholdersAsync(MergeReasons.DirectorySync, cancellationToken);
        }

        // Into Guard's outbox, in a unit of work of its own: the sync, or its failure, has committed already.
        await guardDb.RunAsync(_ => events.PublishAsync(new DirectorySyncCompletedEto(
            directoryId, directoryName, run.Succeeded == true, run.UsersAdded, run.UsersUpdated, run.UsersDeactivated,
            run.GroupsSynced, watch.Elapsed, run.Error), cancellationToken), requiresNew: true, cancellationToken, isTransactional: true);

        return run;
    }

    /// <summary>Applies the directory's users; returns how many names by language were left out for a code that isn't a language's.</summary>
    private static async Task<int> ApplyUsersAsync(GuardDbContext db, UserDirectory directory, List<DirectoryUserRecord> records, SyncRun run, CancellationToken cancellationToken)
    {
        List<DirectoryUser> existing = await db.DirectoryUsers.Where(u => u.DirectoryId == directory.Id).ToListAsync(cancellationToken);
        Dictionary<string, DirectoryUser> byExternalId = existing.ToDictionary(u => u.ExternalId, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, DirectoryUser> byUsername = existing.ToDictionary(u => u.NormalizedUsername);
        HashSet<Guid> seen = [];
        DateTime now = DateTime.UtcNow;
        int leftOut = 0;

        foreach (DirectoryUserRecord record in records.Where(r => !string.IsNullOrWhiteSpace(r.Username)))
        {
            string normalized = GuardConstants.Normalize(record.Username);
            Dictionary<string, string>? names = record.DisplayNames is null ? null : SyncedNames(record.DisplayNames, ref leftOut);
            DirectoryUser? user = byExternalId.GetValueOrDefault(record.ExternalId) ?? byUsername.GetValueOrDefault(normalized);
            if (user is null)
            {
                user = new DirectoryUser(Guid.NewGuid(), directory.Id, record.ExternalId, record.Username);
                db.DirectoryUsers.Add(user);
                byUsername[normalized] = user;
                run.UsersAdded++;
            }
            else if (user.Username != record.Username.Trim() || user.DisplayName != record.DisplayName || user.Email != record.Email
                     || user.IsActive != record.IsActive || user.ExternalId != record.ExternalId || (names is not null && !SameNames(user.DisplayNames, names)))
            {
                run.UsersUpdated++;
            }

            user.ExternalId = record.ExternalId;
            user.SetUsername(record.Username);
            user.DisplayName = record.DisplayName;
            if (names is not null)
            {
                user.DisplayNames = names;
            }
            user.Email = record.Email;
            user.IsActive = record.IsActive;
            user.LastSyncedAt = now;
            seen.Add(user.Id);
        }

        foreach (DirectoryUser missing in existing.Where(u => !seen.Contains(u.Id) && u.IsActive))
        {
            missing.IsActive = false;
            run.UsersDeactivated++;
        }

        return leftOut;
    }

    private static async Task ApplyGroupsAsync(GuardDbContext db, UserDirectory directory, List<DirectoryGroupRecord> records, SyncRun run, CancellationToken cancellationToken)
    {
        // The directory's own group (and organizations) aren't the connector's: only standard and OU groups sync.
        List<Group> existing = await db.Groups.Where(g => g.DirectoryId == directory.Id && (g.Kind == GroupKinds.Standard || g.Kind == GroupKinds.Ou))
            .ToListAsync(cancellationToken);
        Dictionary<string, Group> byExternalId = existing.Where(g => g.ExternalId is not null).ToDictionary(g => g.ExternalId!, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, Group> byName = existing.ToDictionary(g => g.NormalizedName);
        Dictionary<string, Group> recordToGroup = new(StringComparer.OrdinalIgnoreCase);

        foreach (DirectoryGroupRecord record in records)
        {
            Group? group = byExternalId.GetValueOrDefault(record.ExternalId) ?? byName.GetValueOrDefault(GuardConstants.Normalize(record.Name));
            if (group is null)
            {
                group = new Group(Guid.NewGuid(), directory.Id, record.Name, isLocal: false);
                db.Groups.Add(group);
                byName[group.NormalizedName] = group;
            }

            group.ExternalId = record.ExternalId;
            group.SetName(record.Name);
            group.Description = record.Description;
            group.Kind = record.Kind == GroupKinds.Ou ? GroupKinds.Ou : GroupKinds.Standard;
            recordToGroup[record.ExternalId] = group;
            run.GroupsSynced++;
        }

        // Synced groups that vanished from the source are removed with their memberships; local groups stay.
        List<Group> vanished = existing.Where(g => !g.IsLocal && !recordToGroup.ContainsValue(g)).ToList();
        List<Guid> vanishedIds = vanished.Select(g => g.Id).ToList();
        if (vanishedIds.Count > 0)
        {
            await db.Memberships
                .Where(m => vanishedIds.Contains(m.GroupId) || (m.MemberType == MemberType.Group && vanishedIds.Contains(m.MemberId)))
                .ExecuteDeleteAsync(cancellationToken);
            db.Groups.RemoveRange(vanished);
        }

        await db.SaveChangesAsync(cancellationToken);

        // Replace only the rows this directory asserted. Manual rows are never touched.
        List<Guid> groupIds = recordToGroup.Values.Select(g => g.Id).ToList();
        await db.Memberships
            .Where(m => m.Source == MembershipSource.Directory && groupIds.Contains(m.GroupId))
            .ExecuteDeleteAsync(cancellationToken);

        Dictionary<string, Guid> userIds = await db.DirectoryUsers
            .Where(u => u.DirectoryId == directory.Id)
            .ToDictionaryAsync(u => u.ExternalId, u => u.Id, StringComparer.OrdinalIgnoreCase, cancellationToken);

        HashSet<(Guid, MemberType, Guid)> added = [];
        foreach (DirectoryGroupRecord record in records)
        {
            Group parent = recordToGroup[record.ExternalId];
            foreach (string userExternalId in record.MemberUserExternalIds)
            {
                if (userIds.TryGetValue(userExternalId, out Guid userId) && added.Add((parent.Id, MemberType.DirectoryUser, userId)))
                {
                    db.Memberships.Add(new GroupMembership(Guid.NewGuid(), parent.Id, MemberType.DirectoryUser, userId, MembershipSource.Directory));
                }
            }

            foreach (string groupExternalId in record.MemberGroupExternalIds)
            {
                if (recordToGroup.TryGetValue(groupExternalId, out Group? child) && added.Add((parent.Id, MemberType.Group, child.Id)))
                {
                    db.Memberships.Add(new GroupMembership(Guid.NewGuid(), parent.Id, MemberType.Group, child.Id, MembershipSource.Directory));
                }
            }
        }

        run.MembershipsSynced = added.Count;
    }

    private Task PublishAsync(object e, CancellationToken cancellationToken) => e switch
    {
        AccountCreatedEto x => events.PublishAsync(x, cancellationToken),
        AccountUpdatedEto x => events.PublishAsync(x, cancellationToken),
        AccountDeactivatedEto x => events.PublishAsync(x, cancellationToken),
        AccountReactivatedEto x => events.PublishAsync(x, cancellationToken),
        AccountMergedEto x => events.PublishAsync(x, cancellationToken),
        GroupCreatedEto x => events.PublishAsync(x, cancellationToken),
        MembershipChangedEto x => events.PublishAsync(x, cancellationToken),
        _ => Task.CompletedTask,
    };

    private static bool SameNames(IReadOnlyDictionary<string, string>? a, IReadOnlyDictionary<string, string> b) =>
        a is not null && a.Count == b.Count && a.All(n => b.TryGetValue(n.Key, out string? v) && v == n.Value);

    /// <summary>
    /// Names by language were asked for (the connector gave maps, not null) and every person's came back empty: most often
    /// an account that can't read those attributes, which would otherwise clear everyone's names without a word.
    /// </summary>
    internal static bool NoNamesFound(IReadOnlyCollection<DirectoryUserRecord> users) =>
        users.Any(u => u.DisplayNames is not null) && users.All(u => u.DisplayNames is null or { Count: 0 });

    /// <summary>
    /// A directory's names by language as the account keeps them, as a synced display name is treated: trimmed, cut at
    /// the name's length, blank ones left out, and those whose code isn't a language's left out and counted.
    /// </summary>
    internal static Dictionary<string, string> SyncedNames(IReadOnlyDictionary<string, string> names, ref int leftOut)
    {
        Dictionary<string, string> clean = new(StringComparer.Ordinal);
        foreach ((string code, string name) in names)
        {
            string value = (name ?? "").Trim();
            if (value.Length == 0)
            {
                continue;
            }

            if (!DirectoryNames.IsLanguageCode(code?.Trim()))
            {
                leftOut++;
                continue;
            }

            clean[code!.Trim()] = value.Length > AccountCorrections.NameLength ? value[..AccountCorrections.NameLength] : value;
        }

        return clean;
    }
}
