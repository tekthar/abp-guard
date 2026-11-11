using Microsoft.EntityFrameworkCore;
using AbpGuard.Data;
using AbpGuard.Domain;
using Volo.Abp;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>The name as written, and (when given) the person's name in other languages by language code.</summary>
public sealed record AccountNameInput(string DisplayName, Dictionary<string, string>? DisplayNames = null);

/// <summary>
/// Correcting an account (PDPL's right to correction): its display name, and which of its confirmed
/// addresses is its primary. Only an account of the internal directory: a directory's sync writes the others' name and
/// address from the directory on every run, so they're corrected there. The username, which sign-in takes, never
/// changes. Each correction returns the event that tells the host to carry the new name and address to its copies.
/// </summary>
public class AccountCorrections(GuardDb guardDb, IGuardMessenger messenger, IGuardSiteDefaults siteDefaults) : ITransientDependency
{
    public const int NameLength = 200;

    /// <summary>The error code of a correction refused because the account's directory owns its name and address.</summary>
    public const string DirectoryOwned = "directory_owned";

    /// <summary>A new display name for an internal account.</summary>
    public async Task<AccountChangedEto> RenameAsync(Guid accountId, string displayName, CancellationToken ct) =>
        await RenameAsync(accountId, displayName, null, ct);

    /// <summary>
    /// Corrects the name as written and, when <paramref name="displayNames"/> is given, the person's name in other
    /// languages: each 1 to <see cref="NameLength"/> characters, a blank one taken away.
    /// </summary>
    public async Task<AccountChangedEto> RenameAsync(Guid accountId, string displayName, IReadOnlyDictionary<string, string>? displayNames, CancellationToken ct)
    {
        string name = CheckNames(displayName, displayNames);
        return await guardDb.RunAsync(async db =>
        {
            (Account account, DirectoryUser record) = await CorrectableAsync(db, accountId, ct);
            string before = account.DisplayName;
            Dictionary<string, string> namesBefore = new(account.DisplayNames);
            if (displayNames is not null)
            {
                account.SetDisplayNames(displayNames);
            }

            bool othersChanged = displayNames is not null
                && (namesBefore.Count != account.DisplayNames.Count || namesBefore.Any(n => account.DisplayNames.GetValueOrDefault(n.Key) != n.Value));
            if (before == name && !othersChanged)
            {
                throw new UserFriendlyException("That's the name already.");
            }

            (account.DisplayName, record.DisplayName) = (name, name);
            record.DisplayNames = new Dictionary<string, string>(account.DisplayNames);
            await db.SaveChangesAsync(ct);
            return new AccountChangedEto(account.Id, account.Username, before, name, null, null);
        }, requiresNew: true, ct, isTransactional: true);
    }

    /// <summary>
    /// One of the account's confirmed addresses becomes its primary; the primary before stays one of its confirmed
    /// addresses, and is told of the change.
    /// </summary>
    public async Task<AccountChangedEto> SetPrimaryAsync(Guid accountId, Guid emailId, CancellationToken ct)
    {
        (AccountChangedEto changed, string? language) = await guardDb.RunAsync(async db =>
        {
            (Account account, DirectoryUser record) = await CorrectableAsync(db, accountId, ct);
            AccountEmail row = await db.AccountEmails.FirstOrDefaultAsync(e => e.Id == emailId && e.AccountId == accountId && e.VerifiedAt != null, ct)
                ?? throw new UserFriendlyException("Choose one of the account's confirmed addresses.");
            string? before = account.Email;
            db.AccountEmails.Remove(row);
            (account.Email, record.Email) = (row.Email, row.Email);
            if (account.MailTo is not null && string.Equals(account.MailTo, row.Email, StringComparison.OrdinalIgnoreCase))
            {
                account.MailTo = null; // mail goes to the primary now
            }

            if (before is not null)
            {
                db.AccountEmails.Add(new AccountEmail(Guid.NewGuid(), accountId, before, AccountEmailSources.FormerPrimary, accountId) { VerifiedAt = DateTime.UtcNow });
            }

            await db.SaveChangesAsync(ct);
            return (new AccountChangedEto(account.Id, account.Username, null, null, before, row.Email), account.Language);
        }, requiresNew: true, ct, isTransactional: true);

        if (changed.OldEmail is { } old)
        {
            await messenger.SendAsync(new GuardMessage(AddressMail.Changed, null, old, null,
                new Dictionary<string, object?> { ["address"] = changed.NewEmail, ["username"] = changed.Username },
                language ?? siteDefaults.RequestLanguage, "address-changed"), ct);
        }

        return changed;
    }

    /// <summary>
    /// An account's names, checked as a person's are: the name as written, 1 to
    /// <see cref="NameLength"/> characters, and each other language's by a language code, none of them a reserved name.
    /// Returns the name as written, trimmed. A service account's are checked the same way (<see cref="ServiceAccountMaker"/>).
    /// </summary>
    internal static string CheckNames(string? displayName, IReadOnlyDictionary<string, string>? displayNames)
    {
        string name = (displayName ?? "").Trim();
        if (name.Length is 0 or > NameLength)
        {
            throw new UserFriendlyException($"Give a name of 1 to {NameLength} characters.");
        }

        Usernames.EnsureNotReserved(null, name);
        foreach ((string code, string other) in displayNames ?? new Dictionary<string, string>())
        {
            if (code.Length is 0 or > 35 || (other ?? "").Trim().Length > NameLength)
            {
                throw new UserFriendlyException($"Give each language's name in 1 to {NameLength} characters.");
            }

            if (!string.IsNullOrWhiteSpace(other))
            {
                Usernames.EnsureNotReserved(null, other.Trim());
            }
        }

        return name;
    }

    /// <summary>The account and its internal directory's record; a directory's account is refused, naming where to correct it.</summary>
    private static async Task<(Account, DirectoryUser)> CorrectableAsync(GuardDbContext db, Guid accountId, CancellationToken ct)
    {
        Account account = await db.Accounts.FirstOrDefaultAsync(a => a.Id == accountId, ct)
            ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(Account), accountId);
        if (account.MergedIntoId is not null || account.IsService)
        {
            throw new UserFriendlyException("Only a person's own account can be corrected.");
        }

        UserDirectory directory = await db.Directories.AsNoTracking().FirstAsync(d => d.Id == account.DirectoryId, ct);
        DirectoryUser? record = account.DirectoryUserId is { } id ? await db.DirectoryUsers.FirstOrDefaultAsync(u => u.Id == id, ct) : null;
        if (!directory.IsInternal || record is null)
        {
            throw new UserFriendlyException($"This account's name and address come from {directory.Name}: change them there.", DirectoryOwned);
        }

        return (account, record);
    }
}
