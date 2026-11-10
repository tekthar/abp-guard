using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using AbpGuard.Acting;
using AbpGuard.Data;
using AbpGuard.Domain;
using Volo.Abp;
using Volo.Abp.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AbpGuard.Services;

/// <summary>Sign-up as the site has it: on or off, the directory accounts go to, and the email domains it takes.</summary>
public sealed record SignUpSettingsDto(bool Enabled, Guid? DirectoryId, string? DirectoryName, List<string> EmailDomains);

public sealed record SignUpSettingsInput([property: JsonRequired] bool Enabled, Guid? DirectoryId, List<string>? EmailDomains);

/// <summary>What the sign-in page needs to know: whether people may sign up, and with which email domains.</summary>
public sealed record SignUpInfoDto(bool Enabled, List<string> EmailDomains);

/// <summary>A sign-up: the email, a name and a password, and the answer to the site's CAPTCHA (M10 step 7).</summary>
public sealed record SignUpInput(string Email, string DisplayName, string Password, string? Captcha = null);

public sealed record TokenInput(string Token);

public sealed record ForgotPasswordInput(string Email);

public sealed record ResetPasswordInput(string Token, string Password);

/// <summary>The mails self-service sends: confirming an email, and resetting a password.</summary>
public static class SelfServiceMail
{
    public const string Verify = GuardMessageKinds.SignUpVerify;
    public const string Reset = GuardMessageKinds.PasswordReset;

    private static Dictionary<string, string> Text(string en, string ar) => new() { ["en"] = en, ["ar"] = ar };

    public static readonly GuardMessageTemplate VerifyDefinition = new(
        Verify,
        Email: true,
        Text("Confirm your email", "تأكيد البريد"),
        Text("Sent when someone signs up: their account is active once they follow the link.", "تُرسل عند التسجيل: يصبح الحساب فعّالًا عند فتح الرابط."),
        new Dictionary<string, GuardTemplateText>
        {
            ["en"] = new("Confirm your email for {product}",
                "Hello {{ recipient.name }},\n\nConfirm your email to finish creating your account:\n\n[Confirm my email]({{ link }})\n\n"
                + "The link works for {{ hours }} hours. If you didn't sign up, ignore this mail: nothing happens without the link."),
            ["ar"] = new("أكّد بريدك في {product}",
                "مرحبًا {{ recipient.name }}،\n\nأكّد بريدك لإكمال إنشاء حسابك:\n\n[أكّد بريدي]({{ link }})\n\n"
                + "يعمل الرابط لمدة {{ hours }} ساعة. إن لم تسجّل، تجاهل هذه الرسالة: لا يحدث شيء دون الرابط."),
        },
        [
            new("recipient.name", Text("The person who signed up", "الشخص الذي سجّل")),
            new("link", Text("The link that confirms the email", "رابط تأكيد البريد")),
            new("hours", Text("How long the link works", "مدة صلاحية الرابط")),
        ],
        new Dictionary<string, object?>
        {
            ["recipient"] = new Dictionary<string, object?> { ["name"] = "Dana Dev", ["email"] = "dana@example.com", ["time_zone"] = "UTC" },
            ["link"] = "https://example.com/signup/verify#token=sample",
            ["hours"] = 72,
        });

    public static readonly GuardMessageTemplate ResetDefinition = new(
        Reset,
        Email: true,
        Text("Reset a password", "إعادة تعيين كلمة المرور"),
        Text("Sent when someone asks to reset the password of an account {product} keeps.", "تُرسل عند طلب إعادة تعيين كلمة مرور حساب يحفظه {product}."),
        new Dictionary<string, GuardTemplateText>
        {
            ["en"] = new("Reset your {product} password",
                "Hello {{ recipient.name }},\n\nSomeone asked to reset the password of the {product} account {{ username }}. To choose a new one:\n\n[Reset my password]({{ link }})\n\n"
                + "The link works once, for {{ minutes }} minutes. If it wasn't you, ignore this mail: your password stays as it is."),
            ["ar"] = new("أعد تعيين كلمة مرور {product}",
                "مرحبًا {{ recipient.name }}،\n\nطلب أحدهم إعادة تعيين كلمة مرور حساب {product} {{ username }}. لاختيار كلمة جديدة:\n\n[أعد تعيين كلمة المرور]({{ link }})\n\n"
                + "يعمل الرابط مرة واحدة لمدة {{ minutes }} دقيقة. إن لم تكن أنت، تجاهل هذه الرسالة: تبقى كلمة مرورك كما هي."),
        },
        [
            new("recipient.name", Text("The account's owner", "صاحب الحساب")),
            new("username", Text("The account's username", "اسم المستخدم للحساب")),
            new("link", Text("The link to choose a new password", "رابط اختيار كلمة مرور جديدة")),
            new("minutes", Text("How long the link works", "مدة صلاحية الرابط")),
        ],
        new Dictionary<string, object?>
        {
            ["recipient"] = new Dictionary<string, object?> { ["name"] = "Dana Dev", ["email"] = "dana@example.com", ["time_zone"] = "UTC" },
            ["username"] = "dana@example.com",
            ["link"] = "https://example.com/reset-password#token=sample",
            ["minutes"] = 60,
        });
}

/// <summary>
/// Accounts people make and mend themselves: sign-up into the directory the admin names, with the email
/// confirmed by a link before the account is active; and a password reset by mail for accounts Guard keeps (internal
/// directories). Links carry a token from Data Protection that expires, and a reset token is spent once the password
/// changes. Answers never say whether an email has an account, except sign-up, which has to.
/// </summary>
[ExposeServices(typeof(SelfService), typeof(ICustomerAccounts))]
public class SelfService(GuardDb guardDb, AccountProjector projector, IDataProtectionProvider protection, IGuardMessenger messenger, IGuardSiteDefaults siteDefaults, IOptions<GuardOptions> options,
    IGuardEventSink events, AccountMergeService merges, SecurityLog audit, IOptions<GuardNames> names, AccountSessions sessions) : ITransientDependency, ICustomerAccounts
{
    public static readonly TimeSpan VerifyFor = TimeSpan.FromHours(72);
    public static readonly TimeSpan ResetFor = TimeSpan.FromHours(1);

    private ITimeLimitedDataProtector Verifier => protection.CreateProtector(names.Value.Purpose("SignUp.Verify")).ToTimeLimitedDataProtector();
    private ITimeLimitedDataProtector Resetter => protection.CreateProtector(names.Value.Purpose("Password.Reset")).ToTimeLimitedDataProtector();
    private string Site => (options.Value.PublicUrl ?? "http://localhost:3000").TrimEnd('/');

    private string SiteLanguage => options.Value.Site.Languages.FirstOrDefault() ?? "en";

    public Task<SignUpSettingsDto> SettingsAsync(CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        SignUpSettings s = await LoadAsync(db, ct);
        string? name = s.DirectoryId is { } id ? await db.Directories.Where(d => d.Id == id).Select(d => d.Name).FirstOrDefaultAsync(ct) : null;
        return new SignUpSettingsDto(s.Enabled, s.DirectoryId, name, s.EmailDomains);
    }, cancellationToken: ct);

    public async Task<SignUpSettingsDto> SaveSettingsAsync(SignUpSettingsInput input, CancellationToken ct)
    {
        List<string> domains = (input.EmailDomains ?? []).Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(d => Organizations.NormalizeDomain(d) ?? throw new UserFriendlyException($"'{d}' isn't an email domain, such as example.com.")).Distinct().ToList();
        await guardDb.RunAsync(async db =>
        {
            if (input.DirectoryId is { } id)
            {
                UserDirectory directory = await db.Directories.FirstOrDefaultAsync(d => d.Id == id, ct) ?? throw new UserFriendlyException("There's no such directory.");
                if (!directory.IsInternal)
                {
                    throw new UserFriendlyException($"{directory.Name} isn't kept by {options.Value.Texts.Product()}: sign-ups go to an internal directory, such as one called Customers.");
                }
            }
            else if (input.Enabled)
            {
                throw new UserFriendlyException("Choose the directory sign-ups are created in.");
            }

            SignUpSettings s = await LoadAsync(db, ct);
            var before = new { enabled = s.Enabled, directoryId = s.DirectoryId, emailDomains = s.EmailDomains.ToList() };
            (s.Enabled, s.DirectoryId, s.EmailDomains, s.UpdatedAt) = (input.Enabled, input.DirectoryId, domains, DateTime.UtcNow);
            // Who may make themselves an account, and in which directory.
            string? directoryName = s.DirectoryId is { } d ? await db.Directories.Where(x => x.Id == d).Select(x => x.Name).FirstOrDefaultAsync(ct) : null;
            audit.Add(db, SecurityAuditTypes.SignUpChanged, new AbpGuard.Acting.AuditTarget("SignUp", s.DirectoryId, directoryName),
                new { before, after = new { enabled = s.Enabled, directoryId = s.DirectoryId, emailDomains = s.EmailDomains } });
            await db.SaveChangesAsync(ct);
        }, requiresNew: true, ct);
        return await SettingsAsync(ct);
    }

    public Task<SignUpInfoDto> InfoAsync(CancellationToken ct) => guardDb.RunAsync(async db =>
    {
        SignUpSettings s = await LoadAsync(db, ct);
        bool open = s.Enabled && s.DirectoryId is { } id && await db.Directories.AnyAsync(d => d.Id == id && d.IsActive && d.AuthenticationEnabled, ct);
        return new SignUpInfoDto(open, open ? s.EmailDomains : []);
    }, cancellationToken: ct);

    /// <summary>
    /// Creates the account, inactive, and mails a link to confirm the email; signing up again before confirming sends a
    /// new link. The username is the email.
    /// </summary>
    public async Task SignUpAsync(SignUpInput input, CancellationToken ct)
    {
        string email = (input.Email ?? "").Trim();
        string? domain = Organizations.DomainOf(email);
        if (domain is null || !MimeKit.MailboxAddress.TryParse(email, out _) || email.Length > 254)
        {
            throw new UserFriendlyException("Give an email address, such as you@example.com.");
        }

        Password(input.Password);
        string name = string.IsNullOrWhiteSpace(input.DisplayName) ? email : DisplayNames.Check(input.DisplayName.Trim());
        if (name.Length > 200)
        {
            throw new UserFriendlyException("A name is at most 200 characters.");
        }

        string normalized = GuardConstants.Normalize(email);
        DirectoryUser user = await guardDb.RunAsync(async db =>
        {
            SignUpSettings s = await LoadAsync(db, ct);
            UserDirectory? directory = s.Enabled && s.DirectoryId is { } id
                ? await db.Directories.FirstOrDefaultAsync(d => d.Id == id && d.IsActive && d.AuthenticationEnabled, ct)
                : null;
            if (directory is null)
            {
                throw new UserFriendlyException("This site doesn't take sign-ups. Ask its administrator for an account.");
            }

            if (s.EmailDomains.Count > 0 && !s.EmailDomains.Contains(domain))
            {
                throw new UserFriendlyException($"Sign-ups here are for {string.Join(", ", s.EmailDomains.Select(d => "@" + d))} addresses.");
            }

            // Taken: by someone else, or by this email confirmed already. A sign-up still waiting may sign up again. A
            // placeholder from an import takes nothing: its person signs up, and it's merged into them.
            DirectoryUser? pending = await db.DirectoryUsers.FirstOrDefaultAsync(u => u.DirectoryId == directory.Id && u.NormalizedUsername == normalized, ct);
            Guid? waiting = pending?.PendingSince is not null ? pending.Id : null;
            IQueryable<Account> others = Addresses.NotPlaceholders(db, db.Accounts.Where(a => waiting == null || a.DirectoryUserId != waiting));
            bool taken = (pending is not null && waiting is null)
                || await others.AnyAsync(a => a.NormalizedUsername == normalized, ct)
                || await Addresses.NotPlaceholders(db, Addresses.WithAddress(db, normalized)).AnyAsync(a => waiting == null || a.DirectoryUserId != waiting, ct)
                || await db.DirectoryUsers.AnyAsync(u => u.DirectoryId != directory.Id && u.NormalizedUsername == normalized
                    && !db.Directories.Any(d => d.Id == u.DirectoryId && d.Type == AccountProvisioning.ImportedType), ct);
            if (taken)
            {
                throw new UserFriendlyException("This email already has an account. Sign in, or reset its password.");
            }

            DirectoryUser record = pending ?? db.DirectoryUsers.Add(new DirectoryUser(Guid.NewGuid(), directory.Id, $"internal:{normalized}", email)).Entity;
            record.DisplayName = name;
            record.Email = email;
            record.IsActive = false;
            record.PendingSince = DateTime.UtcNow;
            record.PasswordHash = AuthService.HashPassword(record, input.Password);
            await db.SaveChangesAsync(ct);
            await projector.RebuildAsync(db, [normalized], ct);
            await db.SaveChangesAsync(ct);
            return record;
        }, requiresNew: true, ct, isTransactional: true);

        // Bound to the password this sign-up set, as a reset link is: signing up again sets another, and the links mailed
        // before stop working, so following one can't confirm a password someone else chose since.
        string token = Verifier.Protect($"{user.Id:N}:{Stamp(user)}", VerifyFor);
        // The link in the language the person signed up in.
        string link = GuardPageOptions.Link(Site, options.Value.Pages.SignUpVerify, siteDefaults.RequestLanguage);
        await SendAsync(SelfServiceMail.Verify, user, new Dictionary<string, object?> { ["link"] = $"{link}#token={token}", ["hours"] = (int)VerifyFor.TotalHours }, ct);
    }

    /// <summary>Confirms a sign-up's email: the account becomes active, and joins organizations by its domain. Returns its username.</summary>
    public async Task<(string Username, List<object> Events)> VerifyAsync(string token, CancellationToken ct)
    {
        const string Broken = "This link doesn't work: it's wrong, or more than three days old. Sign up again for a new one.";
        string payload;
        try
        {
            payload = Verifier.Unprotect(token ?? "");
        }
        catch (CryptographicException)
        {
            throw new UserFriendlyException(Broken);
        }

        string[] parts = payload.Split(':');
        if (parts.Length != 2 || !Guid.TryParseExact(parts[0], "N", out Guid id))
        {
            throw new UserFriendlyException(Broken);
        }

        (string Username, List<object> Events) verified = await guardDb.RunAsync(async db =>
        {
            DirectoryUser user = await db.DirectoryUsers.FirstOrDefaultAsync(u => u.Id == id, ct)
                ?? throw new UserFriendlyException("This link is for an account that's gone. Sign up again.");
            if (user.PendingSince is null)
            {
                return (user.Username, new List<object>()); // confirmed already: following the link again does nothing
            }

            if (Stamp(user) != parts[1])
            {
                throw new UserFriendlyException("This link was replaced by a newer one: use the latest email, or sign up again.");
            }

            user.PendingSince = null;
            user.IsActive = true;
            await db.SaveChangesAsync(ct);
            List<object> events = await projector.RebuildAsync(db, [user.NormalizedUsername], ct);
            await db.SaveChangesAsync(ct);
            await Organizations.ApplyDomainsAsync(db, ct);
            return (user.Username, events);
        }, requiresNew: true, ct, isTransactional: true);
        await merges.FoldPlaceholdersAsync(MergeReasons.SignUp, ct); // a placeholder with this address joins them
        return verified;
    }

    /// <summary>
    /// The account for someone who confirmed an email (an anonymous portal request): the one active account
    /// with it, else a new one where sign-up allows that address (active: the confirmation verified it; no password until
    /// they set one with a reset), else none.
    /// </summary>
    public Task<Guid?> AccountWithAddressAsync(string email, CancellationToken ct) =>
        guardDb.RunAsync(async db =>
        {
            List<Guid> owners = await Addresses.ActiveWithAddress(db, GuardConstants.Normalize(email)).Select(a => a.Id).Take(2).ToListAsync(ct);
            return owners.Count == 1 ? owners[0] : (Guid?)null;
        }, cancellationToken: ct);

    public async Task<Guid?> AccountForConfirmedEmailAsync(string email, string name, CancellationToken ct)
    {
        string normalized = GuardConstants.Normalize(email);
        string? domain = Organizations.DomainOf(email);
        (Guid? id, List<object> created) = await guardDb.RunAsync(async db =>
        {
            List<Account> owners = await Addresses.ActiveWithAddress(db, normalized).ToListAsync(ct);
            if (owners.Count > 0)
            {
                return (owners.Count == 1 ? owners[0].Id : (Guid?)null, new List<object>());
            }

            SignUpSettings s = await LoadAsync(db, ct);
            UserDirectory? directory = s.Enabled && s.DirectoryId is { } directoryId
                ? await db.Directories.FirstOrDefaultAsync(d => d.Id == directoryId && d.IsActive && d.AuthenticationEnabled, ct)
                : null;
            if (directory is null || domain is null || (s.EmailDomains.Count > 0 && !s.EmailDomains.Contains(domain))
                || await Addresses.NotPlaceholders(db, db.Accounts).AnyAsync(a => a.NormalizedUsername == normalized, ct)
                || await db.DirectoryUsers.AnyAsync(u => u.NormalizedUsername == normalized
                    && !db.Directories.Any(d => d.Id == u.DirectoryId && d.Type == AccountProvisioning.ImportedType), ct))
            {
                return ((Guid?)null, new List<object>());
            }

            DirectoryUser user = db.DirectoryUsers.Add(new DirectoryUser(Guid.NewGuid(), directory.Id, $"internal:{normalized}", email.Trim())
            {
                DisplayName = string.IsNullOrWhiteSpace(name) ? email.Trim() : name.Trim(),
                Email = email.Trim(),
            }).Entity;
            await db.SaveChangesAsync(ct);
            List<object> made = await projector.RebuildAsync(db, [normalized], ct);
            await db.SaveChangesAsync(ct);
            await Organizations.ApplyDomainsAsync(db, ct);
            // In the sign-up's unit of work: the events commit with it.
            foreach (object e in made)
            {
                await Controllers.GuardEvents.PublishAsync(events, e, ct);
            }

            return ((Guid?)await db.Accounts.Where(a => a.NormalizedUsername == normalized).Select(a => a.Id).FirstAsync(ct), made);
        }, requiresNew: true, ct, isTransactional: true);

        if (created.Count > 0)
        {
            await merges.FoldPlaceholdersAsync(MergeReasons.ConfirmedAddress, ct);
        }

        return id;
    }

    /// <summary>Mails a reset link to each active account Guard keeps with this email; nothing for anyone else, and says nothing either way.</summary>
    public async Task ForgotAsync(string email, CancellationToken ct)
    {
        string address = (email ?? "").Trim();
        string normalized = GuardConstants.Normalize(address);
        if (normalized.Length is 0 or > 254)
        {
            return;
        }

        (List<DirectoryUser> users, Dictionary<Guid, string?> languages) = await guardDb.RunAsync(async db =>
        {
            List<Guid> internalDirectories = await db.Directories.Where(d => d.Type == GuardConstants.InternalType && d.IsActive).Select(d => d.Id).ToListAsync(ct);
            List<Guid> owners = await Addresses.ActiveWithAddress(db, normalized).Where(a => a.DirectoryUserId != null).Select(a => a.DirectoryUserId!.Value).ToListAsync(ct);
            List<DirectoryUser> users = await db.DirectoryUsers.AsNoTracking()
                .Where(u => internalDirectories.Contains(u.DirectoryId) && u.IsActive && u.PendingSince == null && owners.Contains(u.Id))
                .ToListAsync(ct);
            List<Guid> ids = users.Select(u => u.Id).ToList();
            Dictionary<Guid, string?> languages = await db.Accounts.AsNoTracking().Where(a => a.DirectoryUserId != null && ids.Contains(a.DirectoryUserId.Value))
                .ToDictionaryAsync(a => a.DirectoryUserId!.Value, a => a.Language, ct);
            return (users, languages);
        }, cancellationToken: ct);

        foreach (DirectoryUser user in users)
        {
            string token = Resetter.Protect($"{user.Id:N}:{Stamp(user)}", ResetFor);
            // The link in the account's language, else the site's.
            string link = GuardPageOptions.Link(Site, options.Value.Pages.PasswordReset, languages.GetValueOrDefault(user.Id) ?? SiteLanguage);
            await SendAsync(SelfServiceMail.Reset, user,
                new Dictionary<string, object?> { ["username"] = user.Username, ["link"] = $"{link}#token={token}", ["minutes"] = (int)ResetFor.TotalMinutes }, ct,
                to: address); // the address asked for: the directory's or one the account verified
        }
    }

    /// <summary>
    /// Sets a new password from a reset link; the link stops working once it has. A reset is how a person takes their
    /// account back, so what was signed in with the old password ends: browsers, the phone app and scripts, and access
    /// tokens. Apps they allowed stay, as when they sign out everywhere.
    /// </summary>
    public async Task<string> ResetAsync(string token, string password, CancellationToken ct)
    {
        Password(password);
        string payload;
        try
        {
            payload = Resetter.Unprotect(token ?? "");
        }
        catch (CryptographicException)
        {
            throw new UserFriendlyException("This link doesn't work: it's wrong, used already, or more than an hour old. Ask for a new one.");
        }

        string[] parts = payload.Split(':');
        (string username, Guid? accountId) = await guardDb.RunAsync<(string, Guid?)>(async db =>
        {
            DirectoryUser? user = parts.Length == 2 && Guid.TryParse(parts[0], out Guid id) ? await db.DirectoryUsers.FirstOrDefaultAsync(u => u.Id == id, ct) : null;
            if (user is null || Stamp(user) != parts[1] || !user.IsActive)
            {
                throw new UserFriendlyException("This link doesn't work: it's wrong, used already, or more than an hour old. Ask for a new one.");
            }

            user.PasswordHash = AuthService.HashPassword(user, password);
            Guid? accountId = await db.Accounts.Where(a => a.DirectoryUserId == user.Id).Select(a => (Guid?)a.Id).FirstOrDefaultAsync(ct);
            if (accountId is { } owner)
            {
                DateTime now = DateTime.UtcNow;
                await db.PersonalAccessTokens.Where(t => t.AccountId == owner && t.RevokedAt == null)
                    .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, now).SetProperty(t => t.RevokedBy, owner), ct);
            }

            audit.Add(db, SecurityAuditTypes.PasswordReset, new AuditTarget("Account", accountId, user.Username));
            await db.SaveChangesAsync(ct);
            return (user.Username, accountId);
        }, requiresNew: true, ct, isTransactional: true);

        if (accountId is { } account)
        {
            await sessions.EndEverywhereAsync(account, null, null, "password-reset", ct);
        }

        return username;
    }

    private async Task SendAsync(string template, DirectoryUser user, Dictionary<string, object?> model, CancellationToken ct, string? to = null) =>
        await messenger.SendAsync(new GuardMessage(template, null, to ?? user.Email!, user.DisplayName, model,
            siteDefaults.RequestLanguage, template == SelfServiceMail.Verify ? "signup" : "password-reset"), ct);

    private static void Password(string? password)
    {
        if (string.IsNullOrEmpty(password) || password.Length < 10 || password.Length > 200)
        {
            throw new UserFriendlyException("Passwords need at least 10 characters.");
        }
    }

    /// <summary>Changes when the password does, so a reset link works once and a sign-up link only for its own password.</summary>
    private static string Stamp(DirectoryUser user) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(user.PasswordHash ?? "")))[..16];

    private async Task<SignUpSettings> LoadAsync(GuardDbContext db, CancellationToken ct) =>
        await db.SignUpSettings.FirstOrDefaultAsync(s => s.Id == SignUpSettings.SiteId, ct) ?? db.SignUpSettings.Add(Initial(options.Value.SignUp)).Entity;

    /// <summary>The site's sign-up settings before an admin chooses: closed, or open into the internal directory.</summary>
    public static SignUpSettings Initial(GuardSignUpOptions defaults) => new(SignUpSettings.SiteId)
    {
        Enabled = defaults.Open,
        DirectoryId = defaults.Open ? GuardConstants.InternalDirectoryId : null,
    };
}

/// <summary>
/// Limits what anyone can ask of the sign-up and reset endpoints from one address: 10 an action in 15 minutes, and 3 mails
/// to one email address an hour. Counted for the whole site (<see cref="IGuardRateLimits"/>), like the sign-in limiter.
/// </summary>
public class SelfServiceLimiter(IGuardRateLimits limits) : ISingletonDependency
{
    public async Task<bool> AllowAsync(string action, string? ip, string? email, CancellationToken cancellationToken = default)
    {
        bool byAddress = await limits.TryTakeAsync($"self-service|{action}|ip|{ip}", 10, TimeSpan.FromMinutes(15), cancellationToken);
        bool byEmail = email is null
            || await limits.TryTakeAsync($"self-service|{action}|mail|{GuardConstants.Normalize(email)}", 3, TimeSpan.FromHours(1), cancellationToken);
        return byAddress && byEmail;
    }
}
