using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using AbpGuard.Data;
using AbpGuard.Domain;
using AbpGuard.Acting;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>
/// People from imports: match by username, then by email; otherwise a deactivated placeholder in an
/// "Imported from {source}" directory, with sign-in off, ranked after every other directory. And a development seeder's
/// people: active accounts in the internal directory, made as an admin makes one.
/// </summary>
[ExposeServices(typeof(IAccountProvisioning))]
public class AccountProvisioning(GuardDb guardDb, AccountProjector projector, IMembershipResolver membership, IGuardEventSink events,
    AccountMergeService merges, SecurityLog audit, Microsoft.Extensions.Options.IOptions<GuardNames> names, Microsoft.Extensions.Options.IOptions<GuardOptions> options)
    : IAccountProvisioning, ITransientDependency
{
    public Task<ProvisionedAccount> EnsureInternalAccountAsync(Guid callerId, string username, string displayName, string? email, string? password,
        CancellationToken cancellationToken = default) =>
        EnsureInternalAccountAsync(callerId, username, displayName, null, email, password, cancellationToken);

    public async Task<ProvisionedAccount> EnsureInternalAccountAsync(Guid callerId, string username, string displayName, IReadOnlyDictionary<string, string>? displayNames,
        string? email, string? password, CancellationToken cancellationToken = default)
    {
        if (!await membership.IsMemberAsync(callerId, GuardWellKnown.AdminsGroupId, cancellationToken))
        {
            throw new UnauthorizedAccessException("Only a site admin makes accounts this way.");
        }

        if (string.IsNullOrWhiteSpace(username) || !Usernames.Pattern().IsMatch(username.Trim()))
        {
            throw new ArgumentException(Usernames.Rule);
        }

        if (Usernames.IsReserved(username) || Usernames.IsReservedName(displayName))
        {
            throw new ArgumentException(Usernames.ReservedRule);
        }

        if (password is not null && password.Length < 10)
        {
            throw new ArgumentException("Passwords need at least 10 characters.");
        }

        string normalized = GuardConstants.Normalize(username);
        int leftOut = 0;
        Dictionary<string, string> names = displayNames is null ? [] : DirectorySyncService.SyncedNames(displayNames, ref leftOut);
        (ProvisionedAccount account, List<object> made) = await guardDb.RunAsync(async db =>
        {
            Account? found = await db.Accounts.FirstOrDefaultAsync(a => a.NormalizedUsername == normalized, cancellationToken);
            if (found is not null)
            {
                // Names filled for the first time are told, so the copies others keep learn the new languages.
                List<object> told = await FillNamesAsync(db, found, names, cancellationToken)
                    ? [new AccountChangedEto(found.Id, found.Username, found.DisplayName, found.DisplayName, null, null)]
                    : [];
                return (new ProvisionedAccount(found.MergedIntoId ?? found.Id, "username"), told);
            }

            DirectoryUser user = new(Guid.NewGuid(), GuardConstants.InternalDirectoryId, $"internal:{normalized}", username.Trim())
            {
                DisplayName = string.IsNullOrWhiteSpace(displayName) ? username.Trim() : displayName.Trim(),
                DisplayNames = names.Count == 0 ? null : names,
                Email = email?.Trim(),
            };
            if (password is not null)
            {
                user.PasswordHash = AuthService.HashPassword(user, password);
            }

            db.DirectoryUsers.Add(user);
            await db.SaveChangesAsync(cancellationToken);
            List<object> events = await projector.RebuildAsync(db, [normalized], cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            await Organizations.ApplyDomainsAsync(db, cancellationToken);
            Account created = await db.Accounts.FirstAsync(a => a.NormalizedUsername == normalized, cancellationToken);
            audit.Add(db, SecurityAuditTypes.AccountCreated, new AuditTarget("Account", created.Id, created.Username), new { directory = options.Value.Texts.Product(), seeded = true });
            await db.SaveChangesAsync(cancellationToken);
            return (new ProvisionedAccount(created.Id, "created"), events);
        }, requiresNew: true, cancellationToken, isTransactional: true);

        foreach (object e in made)
        {
            await Controllers.GuardEvents.PublishAsync(events, e, cancellationToken);
        }

        if (account.MatchedBy == "created")
        {
            await merges.FoldPlaceholdersAsync(MergeReasons.AccountCreated, cancellationToken); // a placeholder with this address joins them
        }

        return account;
    }

    /// <summary>
    /// A person found who has no names by language yet takes the given ones, on the account and on its internal record (so
    /// a rebuild keeps them). True when names were filled.
    /// </summary>
    private static async Task<bool> FillNamesAsync(GuardDbContext db, Account found, Dictionary<string, string> names, CancellationToken ct)
    {
        if (names.Count == 0 || found.DisplayNames.Count > 0 || found.MergedIntoId is not null) // a merged account is no longer the one in use
        {
            return false;
        }

        found.SetDisplayNames(names);
        DirectoryUser? record = found.DirectoryUserId is { } id
            ? await db.DirectoryUsers.FirstOrDefaultAsync(u => u.Id == id && u.DirectoryId == GuardConstants.InternalDirectoryId, ct)
            : null;
        if (record is not null)
        {
            record.DisplayNames = new Dictionary<string, string>(found.DisplayNames);
        }

        await db.SaveChangesAsync(ct);
        return true;
    }

    public const string ImportedType = "imported";

    public Task<ProvisionedAccount> MatchOrCreatePlaceholderAsync(string source, string username, string? displayName, string? email, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(source) || string.IsNullOrWhiteSpace(username))
        {
            throw new ArgumentException("A source and a username are needed.");
        }

        string normalized = GuardConstants.Normalize(username);
        return guardDb.RunAsync(async db =>
        {
            Account? byName = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.NormalizedUsername == normalized, cancellationToken);
            if (byName is not null)
            {
                return new ProvisionedAccount(byName.MergedIntoId ?? byName.Id, "username"); // a merged account lives on in its survivor
            }

            if (!string.IsNullOrWhiteSpace(email))
            {
                string lower = GuardConstants.Normalize(email);
                List<Guid> byEmail = await Addresses.WithAddress(db, lower).AsNoTracking().Select(a => a.Id).Take(2).ToListAsync(cancellationToken);
                if (byEmail.Count == 1)
                {
                    return new ProvisionedAccount(byEmail[0], "email");
                }

                // The address on someone and on placeholders an import made of them (by another name: a site's user key, a
                // Cloud account id): the one account that isn't an import's placeholder is the person (M9 step 7).
                if (byEmail.Count > 1)
                {
                    List<Guid> imported = await db.Directories.AsNoTracking().Where(d => d.Type == ImportedType).Select(d => d.Id).ToListAsync(cancellationToken);
                    List<Guid> people = await Addresses.WithAddress(db, lower).AsNoTracking().Where(a => !imported.Contains(a.DirectoryId))
                        .Select(a => a.Id).Take(2).ToListAsync(cancellationToken);
                    if (people.Count == 1)
                    {
                        return new ProvisionedAccount(people[0], "email");
                    }
                }
            }

            Guid directoryId = DirectoryIdFor(source, names.Value);
            if (!await db.Directories.AnyAsync(d => d.Id == directoryId, cancellationToken))
            {
                int last = await db.Directories.MaxAsync(d => (int?)d.Order, cancellationToken) ?? 0;
                db.Directories.Add(new UserDirectory(directoryId, $"Imported from {source}", ImportedType, last + 1) { AuthenticationEnabled = false });
            }

            db.DirectoryUsers.Add(new DirectoryUser(Guid.NewGuid(), directoryId, $"{ImportedType}:{normalized}", username)
            {
                DisplayName = string.IsNullOrWhiteSpace(displayName) ? username : displayName.Trim(),
                Email = email?.Trim(),
                IsActive = false, // deactivated until an admin acts, or a ranking directory takes the username over
            });
            await db.SaveChangesAsync(cancellationToken);
            await projector.RebuildAsync(db, [normalized], cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            Account created = await db.Accounts.AsNoTracking().FirstAsync(a => a.NormalizedUsername == normalized, cancellationToken);
            return new ProvisionedAccount(created.Id, "placeholder");
        }, requiresNew: true, cancellationToken, isTransactional: true);
    }

    /// <summary>One directory per source, with an id derived from its name, so reruns and other importers share it.</summary>
    public static Guid DirectoryIdFor(string source, GuardNames names) =>
        new(SHA256.HashData(Encoding.UTF8.GetBytes(names.ImportedDirectorySalt + source.Trim().ToLowerInvariant()))[..16]);
}
