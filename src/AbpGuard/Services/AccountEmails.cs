using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using AbpGuard.Data;
using AbpGuard.Domain;
using Volo.Abp;
using Volo.Abp.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AbpGuard.Services;

/// <summary>
/// Who has an address: an account's directory address, or one of its own it verified. Every match by email
/// goes through here, so all of an account's addresses count everywhere.
/// </summary>
public static class Addresses
{
    /// <summary>An address as compared: trimmed, lower case; null when it isn't one.</summary>
    public static string? Normalize(string? email)
    {
        string value = (email ?? "").Trim();
        return value.Length is > 0 and <= 254 && Organizations.DomainOf(value) is not null && MimeKit.MailboxAddress.TryParse(value, out _)
            ? GuardConstants.Normalize(value)
            : null;
    }

    /// <summary>Accounts (not merged) with this address, the directory's or a verified one of their own, in any state.</summary>
    public static IQueryable<Account> WithAddress(GuardDbContext db, string normalized)
    {
        string pattern = SqlLike.Exactly(normalized);
        return db.Accounts.Where(a => a.MergedIntoId == null
            && ((a.Email != null && EF.Functions.ILike(a.Email, pattern))
                || db.AccountEmails.Any(e => e.AccountId == a.Id && e.VerifiedAt != null && e.NormalizedEmail == normalized)));
    }

    /// <summary>The active accounts with this address.</summary>
    public static IQueryable<Account> ActiveWithAddress(GuardDbContext db, string normalized) =>
        WithAddress(db, normalized).Where(a => a.Status == AccountStatus.Active);

    /// <summary>
    /// Placeholders: accounts from an "Imported from …" directory that are inactive, never signed in and not
    /// merged. They never stop a real person from having their address, and are merged into them.
    /// </summary>
    public static IQueryable<Account> Placeholders(GuardDbContext db) =>
        db.Accounts.Where(a => a.MergedIntoId == null && a.Status != AccountStatus.Active && a.LastLoginAt == null
            && db.Directories.Any(d => d.Id == a.DirectoryId && d.Type == AccountProvisioning.ImportedType));

    public static IQueryable<Account> NotPlaceholders(GuardDbContext db, IQueryable<Account> accounts) =>
        accounts.Where(a => !(a.Status != AccountStatus.Active && a.LastLoginAt == null
            && db.Directories.Any(d => d.Id == a.DirectoryId && d.Type == AccountProvisioning.ImportedType)));

    /// <summary>Every address each of these accounts has (lower case): the directory's and the verified ones.</summary>
    public static async Task<Dictionary<Guid, HashSet<string>>> OfAsync(GuardDbContext db, IReadOnlyCollection<Guid> accountIds, CancellationToken ct)
    {
        Dictionary<Guid, HashSet<string>> all = accountIds.Distinct().ToDictionary(id => id, _ => new HashSet<string>());
        foreach (var a in await db.Accounts.AsNoTracking().Where(a => accountIds.Contains(a.Id) && a.Email != null).Select(a => new { a.Id, a.Email }).ToListAsync(ct))
        {
            all[a.Id].Add(GuardConstants.Normalize(a.Email!));
        }

        foreach (var e in await db.AccountEmails.AsNoTracking().Where(e => accountIds.Contains(e.AccountId) && e.VerifiedAt != null)
                     .Select(e => new { e.AccountId, e.NormalizedEmail }).ToListAsync(ct))
        {
            all[e.AccountId].Add(e.NormalizedEmail);
        }

        return all;
    }
}

public sealed record AccountEmailDto(Guid Id, string Email, string Source, DateTime? VerifiedAt, DateTime AddedAt, bool MailGoesHere);

/// <summary>
/// An account's addresses: its directory's, its own, and the one mail goes to. Correctable when its name and
/// primary are corrected here (the internal directory's account); else Directory names where they're corrected.
/// </summary>
public sealed record AccountEmailsDto(string? DirectoryEmail, string? MailTo, bool DirectoryMailGoesHere, List<AccountEmailDto> Addresses)
{
    public bool Correctable { get; init; }

    public string? Directory { get; init; }
}

public sealed record AddEmailInput(string Email);

public sealed record MailToInput(string? Email);

/// <summary>The mail that confirms an address someone added to their account.</summary>
public static class AddressMail
{
    public const string Verify = GuardMessageKinds.AddressVerify;

    private static Dictionary<string, string> Text(string en, string ar) => new() { ["en"] = en, ["ar"] = ar };

    public static readonly GuardMessageTemplate VerifyDefinition = new(
        Verify,
        Email: true,
        Text("Confirm an added address", "تأكيد عنوان مضاف"),
        Text("Sent when someone adds an address to their account: it counts once they follow the link.", "تُرسل عند إضافة عنوان إلى حساب: يُعتمد عند فتح الرابط."),
        new Dictionary<string, GuardTemplateText>
        {
            ["en"] = new("Confirm {{ address }} for {product}",
                "Hello {{ recipient.name }},\n\nConfirm that {{ address }} is yours, to add it to the {product} account {{ username }}:\n\n[Confirm this address]({{ link }})\n\n"
                + "The link works for {{ hours }} hours. If you didn't add it, ignore this mail: nothing happens without the link."),
            ["ar"] = new("أكّد {{ address }} في {product}",
                "مرحبًا {{ recipient.name }}،\n\nأكّد أن {{ address }} عنوانك، لإضافته إلى حساب {product} {{ username }}:\n\n[أكّد هذا العنوان]({{ link }})\n\n"
                + "يعمل الرابط لمدة {{ hours }} ساعة. إن لم تضفه، تجاهل هذه الرسالة: لا يحدث شيء دون الرابط."),
        },
        [
            new("recipient.name", Text("The account's owner", "صاحب الحساب")),
            new("address", Text("The address being added", "العنوان المضاف")),
            new("username", Text("The account's username", "اسم المستخدم للحساب")),
            new("link", Text("The link that confirms the address", "رابط تأكيد العنوان")),
            new("hours", Text("How long the link works", "مدة صلاحية الرابط")),
        ],
        new Dictionary<string, object?>
        {
            ["recipient"] = new Dictionary<string, object?> { ["name"] = "Dana Dev", ["email"] = "dana@home.example", ["time_zone"] = "UTC" },
            ["address"] = "dana@home.example",
            ["username"] = "dana",
            ["link"] = "https://example.com/emails/verify#token=sample",
            ["hours"] = 72,
        });

    public const string Changed = GuardMessageKinds.AddressChanged;

    /// <summary>
    /// Telling an address that it's no longer an account's primary (a correction): if the person didn't
    /// make the change, they hear of it at the address they had.
    /// </summary>
    public static readonly GuardMessageTemplate ChangedDefinition = new(
        Changed,
        Email: true,
        Text("A primary address changed", "تغيّر العنوان الرئيسي"),
        Text("Sent to an account's former primary address when another of its confirmed addresses takes its place.",
            "تُرسل إلى العنوان الرئيسي السابق للحساب حين يحلّ محله عنوان آخر مؤكَّد من عناوينه."),
        new Dictionary<string, GuardTemplateText>
        {
            ["en"] = new("Your {product} account's address changed",
                "Hello,\n\nThe {product} account {{ username }} now uses {{ address }} as its primary address. This address stays one of its "
                + "confirmed addresses.\n\nIf you didn't make this change, tell your site's administrators at once."),
            ["ar"] = new("تغيّر عنوان حسابك في {product}",
                "مرحبًا،\n\nأصبح حساب {product} {{ username }} يستخدم {{ address }} عنوانًا رئيسيًا. ويبقى هذا العنوان من عناوينه المؤكَّدة."
                + "\n\nإن لم تُجرِ هذا التغيير، فأخبر مشرفي موقعك فورًا."),
        },
        [
            new("username", Text("The account's username", "اسم المستخدم للحساب")),
            new("address", Text("The new primary address", "العنوان الرئيسي الجديد")),
        ],
        new Dictionary<string, object?>
        {
            ["username"] = "dana",
            ["address"] = "dana@home.example",
        });
}

/// <summary>
/// The addresses an account has besides its directory's. An admin's are verified at once; a person's once they
/// follow a link mailed to the address. A verified address belongs to one account: adding one another account has is
/// refused, except a placeholder's, which is then merged into this account.
/// </summary>
public class AccountEmailService(GuardDb guardDb, IDataProtectionProvider protection, IGuardMessenger messenger, IGuardSiteDefaults siteDefaults, IOptions<GuardOptions> options, AccountMergeService merges,
    IOptions<GuardNames> names)
    : ITransientDependency
{
    public const int MaxAddresses = 20;
    public static readonly TimeSpan VerifyFor = TimeSpan.FromHours(72);

    private ITimeLimitedDataProtector Verifier => protection.CreateProtector(names.Value.Purpose("Email.Verify")).ToTimeLimitedDataProtector();
    private string Site => (options.Value.PublicUrl ?? "http://localhost:3000").TrimEnd('/');

    public Task<AccountEmailsDto> ListAsync(Guid accountId, CancellationToken ct) => guardDb.RunAsync(db => LoadAsync(db, accountId, ct), cancellationToken: ct);

    internal static async Task<AccountEmailsDto> LoadAsync(GuardDbContext db, Guid accountId, CancellationToken ct)
    {
        Account account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, ct)
            ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(Account), accountId);
        List<AccountEmail> rows = await db.AccountEmails.AsNoTracking().Where(e => e.AccountId == accountId).OrderBy(e => e.AddedAt).ToListAsync(ct);
        string? mailTo = account.MailAddress;
        UserDirectory? directory = await db.Directories.AsNoTracking().FirstOrDefaultAsync(d => d.Id == account.DirectoryId, ct);
        return new AccountEmailsDto(account.Email, account.MailTo, account.MailTo is null && account.Email is not null,
            rows.Select(e => new AccountEmailDto(e.Id, e.Email, e.Source, e.VerifiedAt, e.AddedAt,
                account.MailTo is not null && e.VerifiedAt is not null && string.Equals(e.Email, mailTo, StringComparison.OrdinalIgnoreCase))).ToList())
        {
            Correctable = directory?.IsInternal == true && account.DirectoryUserId is not null && !account.IsService && account.MergedIntoId is null,
            Directory = directory?.Name,
        };
    }

    /// <summary>An admin adds an address: verified at once. A placeholder with it is merged into the account.</summary>
    public async Task<AccountEmailsDto> AddVerifiedAsync(Guid accountId, string email, Guid adminId, CancellationToken ct)
    {
        string normalized = Addresses.Normalize(email) ?? throw new UserFriendlyException("Give an email address, such as someone@example.com.");
        await guardDb.RunAsync(async db =>
        {
            Account account = await TargetAsync(db, accountId, ct);
            AccountEmail? mine = await CheckFreeAsync(db, account, normalized, nameOthers: true, ct);
            if (mine is null)
            {
                mine = db.AccountEmails.Add(new AccountEmail(Guid.NewGuid(), accountId, email, AccountEmailSources.Admin, adminId)).Entity;
            }

            mine.VerifiedAt = DateTime.UtcNow;
            await db.SaveChangesAsync(ct);
            await Organizations.ApplyDomainsAsync(db, ct);
        }, requiresNew: true, ct, isTransactional: true);
        await merges.FoldPlaceholdersAsync(MergeReasons.AddressAdded, ct);
        return await ListAsync(accountId, ct);
    }

    /// <summary>A person adds an address: it waits until they follow the link mailed to it.</summary>
    public async Task<AccountEmailsDto> AddForSelfAsync(Guid accountId, string email, CancellationToken ct)
    {
        string normalized = Addresses.Normalize(email) ?? throw new UserFriendlyException("Give an email address, such as you@example.com.");
        (AccountEmail row, Account account) = await guardDb.RunAsync(async db =>
        {
            Account account = await TargetAsync(db, accountId, ct);
            AccountEmail? mine = await CheckFreeAsync(db, account, normalized, nameOthers: false, ct);
            if (mine?.VerifiedAt is not null)
            {
                throw new UserFriendlyException("That address is yours already.");
            }

            mine ??= db.AccountEmails.Add(new AccountEmail(Guid.NewGuid(), accountId, email, AccountEmailSources.Person, accountId)).Entity;
            await db.SaveChangesAsync(ct);
            return (mine, account);
        }, requiresNew: true, ct);

        string token = Verifier.Protect(row.Id.ToString("N"), VerifyFor);
        await messenger.SendAsync(new GuardMessage(AddressMail.Verify, null, row.Email, account.DisplayName,
            new Dictionary<string, object?>
            {
                ["address"] = row.Email,
                ["username"] = account.Username,
                // The link in the account's language, else the site's.
                ["link"] = $"{GuardPageOptions.Link(Site, options.Value.Pages.AddressVerify, account.Language ?? options.Value.Site.Languages.FirstOrDefault())}#token={token}",
                ["hours"] = (int)VerifyFor.TotalHours,
            }, account.Language ?? siteDefaults.RequestLanguage, "address-verify"), ct);
        return await ListAsync(accountId, ct);
    }

    /// <summary>Confirms an address from its link. Returns the address and the account's username.</summary>
    public async Task<(string Email, string Username)> VerifyAsync(string token, CancellationToken ct)
    {
        Guid id;
        try
        {
            id = Guid.ParseExact(Verifier.Unprotect(token ?? ""), "N");
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new UserFriendlyException("This link doesn't work: it's wrong, or more than three days old. Add the address again for a new one.");
        }

        (string Email, string Username, bool Changed) result = await guardDb.RunAsync(async db =>
        {
            AccountEmail row = await db.AccountEmails.FirstOrDefaultAsync(e => e.Id == id, ct)
                ?? throw new UserFriendlyException("This link is for an address that was removed. Add it again for a new one.");
            Account account = await db.Accounts.FirstAsync(a => a.Id == row.AccountId, ct);
            if (row.VerifiedAt is not null)
            {
                return (row.Email, account.Username, false); // confirmed already: following the link again does nothing
            }

            await CheckFreeAsync(db, account, row.NormalizedEmail, nameOthers: false, ct);
            row.VerifiedAt = DateTime.UtcNow;
            await db.SaveChangesAsync(ct);
            await Organizations.ApplyDomainsAsync(db, ct);
            return (row.Email, account.Username, true);
        }, requiresNew: true, ct, isTransactional: true);

        if (result.Changed)
        {
            await merges.FoldPlaceholdersAsync(MergeReasons.AddressAdded, ct);
        }

        return (result.Email, result.Username);
    }

    public async Task<AccountEmailsDto> RemoveAsync(Guid accountId, Guid emailId, CancellationToken ct)
    {
        await guardDb.RunAsync(async db =>
        {
            AccountEmail row = await db.AccountEmails.FirstOrDefaultAsync(e => e.Id == emailId && e.AccountId == accountId, ct)
                ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(AccountEmail), emailId);
            Account account = await db.Accounts.FirstAsync(a => a.Id == accountId, ct);
            if (account.MailTo is not null && GuardConstants.Normalize(account.MailTo) == row.NormalizedEmail)
            {
                account.MailTo = null; // mail goes to the directory's address again
            }

            db.AccountEmails.Remove(row);
            await db.SaveChangesAsync(ct);
            await Organizations.ApplyDomainsAsync(db, ct);
        }, requiresNew: true, ct, isTransactional: true);
        return await ListAsync(accountId, ct);
    }

    /// <summary>Where mail goes: one of the account's verified addresses, or null (or the directory's) for the directory's.</summary>
    public async Task<AccountEmailsDto> SetMailToAsync(Guid accountId, string? email, CancellationToken ct)
    {
        await guardDb.RunAsync(async db =>
        {
            Account account = await TargetAsync(db, accountId, ct);
            string? normalized = string.IsNullOrWhiteSpace(email) ? null : GuardConstants.Normalize(email);
            if (normalized is null || (account.Email is not null && GuardConstants.Normalize(account.Email) == normalized))
            {
                account.MailTo = null;
            }
            else
            {
                AccountEmail row = await db.AccountEmails.FirstOrDefaultAsync(e => e.AccountId == accountId && e.NormalizedEmail == normalized && e.VerifiedAt != null, ct)
                    ?? throw new UserFriendlyException("Mail can only go to one of the account's confirmed addresses.");
                account.MailTo = row.Email;
            }

            await db.SaveChangesAsync(ct);
        }, requiresNew: true, ct);
        return await ListAsync(accountId, ct);
    }

    private static async Task<Account> TargetAsync(GuardDbContext db, Guid accountId, CancellationToken ct)
    {
        Account account = await db.Accounts.FirstOrDefaultAsync(a => a.Id == accountId, ct)
            ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(Account), accountId);
        if (account.MergedIntoId is not null)
        {
            throw new UserFriendlyException($"{account.Username} was merged into another account: its addresses are that account's now.");
        }

        return account;
    }

    /// <summary>
    /// Refuses an address another account has (as its directory's, or verified), naming it for admins. A placeholder's
    /// doesn't count: it's merged into this account once the address is verified. Returns this account's own row for it,
    /// if it has one.
    /// </summary>
    private static async Task<AccountEmail?> CheckFreeAsync(GuardDbContext db, Account account, string normalized, bool nameOthers, CancellationToken ct)
    {
        if (account.Email is not null && GuardConstants.Normalize(account.Email) == normalized)
        {
            throw new UserFriendlyException("That's the account's address from its directory already.");
        }

        List<AccountEmail> mine = await db.AccountEmails.Where(e => e.AccountId == account.Id).ToListAsync(ct);
        if (mine.Count >= MaxAddresses && mine.All(e => e.NormalizedEmail != normalized))
        {
            throw new UserFriendlyException($"An account has at most {MaxAddresses} addresses of its own.");
        }

        string? other = await Addresses.NotPlaceholders(db, Addresses.WithAddress(db, normalized)).Where(a => a.Id != account.Id)
            .Select(a => a.Username).FirstOrDefaultAsync(ct);
        if (other is not null)
        {
            throw new UserFriendlyException(nameOthers
                ? $"{normalized} is {other}'s address. If they're the same person, merge the two accounts."
                : "That address belongs to another account.");
        }

        return mine.FirstOrDefault(e => e.NormalizedEmail == normalized);
    }
}
