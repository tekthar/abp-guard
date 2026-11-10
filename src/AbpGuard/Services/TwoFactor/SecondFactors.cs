using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using AbpGuard.Data;
using AbpGuard.Domain;
using AbpGuard.Acting;
using QRCoder;
using Volo.Abp;
using Volo.Abp.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AbpGuard.Services.TwoFactor;

/// <summary>A password that was right but isn't enough: the ticket for the second step, and what it may be.</summary>
/// <param name="Ticket">Good once, for five minutes and five tries.</param>
/// <param name="Methods">The person's methods that the step takes (<c>app</c>); empty when <paramref name="Enrol"/>.</param>
/// <param name="Enrol">The person has none yet and must set one up with the ticket first.</param>
/// <param name="Strong">Only a strong method will do (the app), as one of their groups asks.</param>
/// <param name="Senders">The methods among them whose code is sent, with where it would go (masked).</param>
public sealed record SecondFactorChallengeDto(string Ticket, List<string> Methods, bool Enrol, bool Strong, DateTime ExpiresAt, List<SecondFactorSenderDto>? Senders = null);

/// <summary>A way a code can be sent to the person: the method (<c>email</c>, a channel's key), its name, and where, masked.</summary>
public sealed record SecondFactorSenderDto(string Method, string Name, string To);

/// <summary>A code sent: how, where (masked), and until when it works.</summary>
public sealed record CodeSentDto(string Method, string To, DateTime ExpiresAt);

/// <summary>
/// Sending a code: sent, or why not (<c>ticket_expired</c>; <c>method_not_allowed</c>: the site doesn't allow it, or a
/// strong group asks for the app; <c>unreachable</c>: no address for it; <c>too_many_attempts</c>; <c>not_sent</c>: the
/// channel failed).
/// </summary>
public sealed record SendCodeResult(CodeSentDto? Sent, string? Error);

/// <summary>Setting up the authenticator app: the secret (to type in), the address and its QR code (a PNG data URL).</summary>
public sealed record AppEnrolmentDto(string Secret, string Address, string Qr);

/// <summary>A second factor set up; the recovery codes when they were made now, shown this once.</summary>
public sealed record SecondFactorEnrolledDto(List<string>? RecoveryCodes);

public sealed record SecondFactorDto(Guid Id, string Kind, DateTime CreatedAt, DateTime? LastUsedAt);

/// <summary>A person's second factors: what their groups ask (<see cref="TwoFactorModes"/>), what they have, the recovery codes left.</summary>
public sealed record MySecondFactorsDto(string Mode, bool Asked, List<SecondFactorDto> Factors, int RecoveryCodesLeft, bool Disabled,
    List<SecondFactorSenderDto>? Senders = null);

/// <summary>A ticket's second step passed: who, for which client and scopes.</summary>
public sealed record SecondStepPassed(Guid AccountId, string Client, string? Scopes);

/// <summary>
/// The second step's outcome: passed, or why not (<c>ticket_expired</c>: used, too old or out of tries, or another
/// client's; <c>too_many_attempts</c>: too many wrong codes for the person; <c>second_factor_failed</c>: a wrong code).
/// </summary>
public sealed record SecondStepResult(SecondStepPassed? Passed, string? Error);

/// <summary>
/// A second factor: which people are asked (the strictest mode of their groups, or having set one up), the
/// tickets of the second step, the authenticator app and recovery codes, setting up, removing and an admin's reset. The
/// app's secret is encrypted with the site's key ring; tickets and recovery codes are kept as their SHA-256. Wrong codes
/// count for the whole site (<see cref="IGuardRateLimits"/>), ten in 15 minutes per person, and five per ticket.
/// <c>Guard:TwoFactor:Disabled</c> asks no one: the emergency switch, for a site whose admins all lost their phones.
/// </summary>
public sealed class SecondFactors(
    GuardDb guardDb,
    MembershipGraph graph,
    IDataProtectionProvider protection,
    IGuardRateLimits limits,
    SecurityLog audit,
    IConfiguration configuration,
    IOptions<GuardOptions> options,
    IGuardMessenger messenger,
    ILogger<SecondFactors> logger,
    IOptions<GuardNames> names) : ITransientDependency
{
    public const int RecoveryCodeCount = 10;
    private const int MaxWrongCodes = 10;
    private static readonly TimeSpan WrongCodesWindow = TimeSpan.FromMinutes(15);

    // Codes sent: five a person in 15 minutes, three a sign-in.
    private const int MaxSends = 5;
    private const int MaxSendsPerTicket = 3;
    private const string RecoveryAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

    private IDataProtector Protector => protection.CreateProtector(names.Value.Purpose("SecondFactor.v1"));

    /// <summary>The emergency switch: nobody is asked for a second factor.</summary>
    public bool Disabled => configuration.GetValue("Guard:TwoFactor:Disabled", false) || !options.Value.Features.TwoFactor;

    /// <summary>The strictest mode of every group the person is in, directly, nested or synced.</summary>
    public async Task<string> ModeAsync(GuardDbContext db, Account account, CancellationToken cancellationToken)
    {
        if (Disabled)
        {
            return TwoFactorModes.Off;
        }

        List<EffectiveGroup> groups = await graph.GetEffectiveGroupsAsync(db, account, cancellationToken);
        return TwoFactorModes.Strictest(groups.Select(g => g.Group.TwoFactor));
    }

    /// <summary>
    /// After a right password: null when no second step is asked, else a ticket for it. A person is asked when a group of
    /// theirs requires it, or when they set a second factor up themselves.
    /// </summary>
    public Task<SecondFactorChallengeDto?> ChallengeAsync(Guid accountId, string client, string? scopes, string? ip, CancellationToken cancellationToken) =>
        guardDb.RunAsync<SecondFactorChallengeDto?>(async db =>
        {
            Account account = await db.Accounts.AsNoTracking().FirstAsync(a => a.Id == accountId, cancellationToken);
            string mode = await ModeAsync(db, account, cancellationToken);
            List<string> kinds = await db.SecondFactors.AsNoTracking().Where(f => f.AccountId == accountId && f.ConfirmedAt != null).Select(f => f.Kind)
                .Distinct().ToListAsync(cancellationToken);
            if (Disabled || (!TwoFactorModes.Asks(mode) && kinds.Count == 0))
            {
                return null;
            }

            // The app first; then the codes the site sends, by what reaches the person, unless a strong group asks for the app.
            bool strong = mode == TwoFactorModes.Strong;
            List<SecondFactorSenderDto> senders = strong ? [] : await SendersAsync(db, account, cancellationToken);
            List<string> methods = [.. kinds.Where(k => !strong || SecondFactorKinds.IsStrong(k)).Order(StringComparer.Ordinal), .. senders.Select(s => s.Method)];
            // Recovery codes stand in for a factor; listed only where the host's clients read them (GuardOptions.TwoFactor).
            if (options.Value.TwoFactor.ListsRecovery && methods.Count > 0
                && await db.RecoveryCodes.AnyAsync(c => c.AccountId == accountId && c.UsedAt == null, cancellationToken))
            {
                methods.Add(SecondFactorKinds.Recovery);
            }

            string ticket = Secret();
            SignInTicket row = new(Guid.NewGuid(), accountId, Hash(ticket), client, scopes, ip);
            db.SignInTickets.Add(row);
            await db.SignInTickets.Where(t => t.ExpiresAt < DateTime.UtcNow).ExecuteDeleteAsync(cancellationToken);
            await db.SentCodes.Where(c => c.ExpiresAt < DateTime.UtcNow).ExecuteDeleteAsync(cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            return new SecondFactorChallengeDto(ticket, methods, methods.Count == 0, strong, row.ExpiresAt, senders);
        }, requiresNew: true, cancellationToken);

    /// <summary>
    /// The second step: the ticket and a code of the method (the app, or a recovery code), or a ticket a second factor was
    /// just set up with. Passed, the ticket is used up. Wrong, it's a try less; refused outright when the client isn't the
    /// one that checked the password, or the person has had too many wrong codes.
    /// </summary>
    public async Task<SecondStepResult> PassAsync(string ticket, string? method, string? code, string client, string? ip, CancellationToken cancellationToken)
    {
        string hash = Hash(ticket);
        (SecondStepPassed? passed, Guid? accountId, string? username, string? why) = await guardDb.RunAsync<(SecondStepPassed?, Guid?, string?, string?)>(async db =>
        {
            DateTime now = DateTime.UtcNow;
            SignInTicket? row = await db.SignInTickets.FirstOrDefaultAsync(t => t.TicketHash == hash, cancellationToken);
            if (row is null || !row.Usable(now) || row.Client != client)
            {
                return (null, row?.AccountId, null, "ticket");
            }

            Account? account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == row.AccountId, cancellationToken);
            if (account is null || account.Status != AccountStatus.Active)
            {
                db.SignInTickets.Remove(row);
                await db.SaveChangesAsync(cancellationToken);
                return (null, row.AccountId, account?.Username, "account");
            }

            if (row.ProvedAt is null)
            {
                // The ticket's try and the person's are taken before the code is checked, so codes sent at once can't
                // all be checked before the first wrong one counts; a right code gives the person's back.
                if (await db.SignInTickets.Where(t => t.Id == row.Id && t.Attempts < SignInTicket.MaxAttempts)
                        .ExecuteUpdateAsync(u => u.SetProperty(t => t.Attempts, t => t.Attempts + 1), cancellationToken) == 0)
                {
                    return (null, account.Id, account.Username, "ticket");
                }

                if (!await limits.TryTakeAsync(WrongKey(account.Id), MaxWrongCodes, WrongCodesWindow, cancellationToken))
                {
                    return (null, account.Id, account.Username, "blocked");
                }

                bool strong = await ModeAsync(db, account, cancellationToken) == TwoFactorModes.Strong;
                if (!await CheckCodeAsync(db, account.Id, method, code, strong, now, cancellationToken))
                {
                    return (null, account.Id, account.Username, "code");
                }

                await limits.ResetAsync(WrongKey(account.Id), cancellationToken);
            }

            // The ticket passes once: of two passes at once, only the one that removes it.
            if (await db.SignInTickets.Where(t => t.Id == row.Id).ExecuteDeleteAsync(cancellationToken) == 0)
            {
                return (null, account.Id, account.Username, "ticket");
            }

            return (new SecondStepPassed(account.Id, row.Client, row.Scopes), account.Id, account.Username, null);
        }, requiresNew: true, cancellationToken);

        await audit.WriteAsync(passed is null ? SecurityAuditTypes.SecondFactorFailed : SecurityAuditTypes.SecondFactorSucceeded, username, accountId,
            passed is null ? why : method, ip, cancellationToken);
        return new SecondStepResult(passed, passed is not null ? null : why switch
        {
            "blocked" => "too_many_attempts",
            "code" => "second_factor_failed",
            _ => "ticket_expired",
        });
    }

    /// <summary>
    /// A step-up's second factor, after the right password: null when it passes (the person has none, or the code is
    /// right), else <c>second_factor_required</c> (no code), <c>second_factor_failed</c> or <c>too_many_attempts</c>.
    /// Wrong codes count with the sign-in's, so a session and a password can't be used to guess them.
    /// </summary>
    public async Task<string?> StepUpErrorAsync(Guid accountId, string? method, string? code, string? ip, CancellationToken cancellationToken)
    {
        (string? error, string? username) = await guardDb.RunAsync<(string?, string?)>(async db =>
        {
            if (Disabled)
            {
                return (null, null);
            }

            // Asked as at sign-in: someone with the app; or someone a group asks, by a code the site sends them. One with
            // no way to give a code yet passes, or they could never step up to set the app up.
            Account account = await db.Accounts.AsNoTracking().FirstAsync(a => a.Id == accountId, cancellationToken);
            if (!await db.SecondFactors.AnyAsync(f => f.AccountId == accountId && f.ConfirmedAt != null, cancellationToken)
                && (await ModeAsync(db, account, cancellationToken) is var mode && (!TwoFactorModes.Asks(mode) || mode == TwoFactorModes.Strong)
                    || (await SendersAsync(db, account, cancellationToken)).Count == 0))
            {
                return (null, null);
            }

            if (code is not { Length: > 0 })
            {
                return ("second_factor_required", account.Username);
            }

            // Taken before the check, as at sign-in; a right code gives it back.
            if (!await limits.TryTakeAsync(WrongKey(accountId), MaxWrongCodes, WrongCodesWindow, cancellationToken))
            {
                return ("too_many_attempts", account.Username);
            }

            bool strong = await ModeAsync(db, account, cancellationToken) == TwoFactorModes.Strong;
            if (await CheckCodeAsync(db, accountId, method, code, strong, DateTime.UtcNow, cancellationToken))
            {
                await limits.ResetAsync(WrongKey(accountId), cancellationToken);
                return (null, account.Username);
            }

            return ("second_factor_failed", account.Username);
        }, requiresNew: true, cancellationToken);

        if (error is "second_factor_failed" or "too_many_attempts")
        {
            await audit.WriteAsync(SecurityAuditTypes.SecondFactorFailed, username, accountId, "step-up", ip, cancellationToken);
        }

        return error;
    }

    /// <summary>Whether the person has a second factor set up (a step-up then asks for a code too).</summary>
    public Task<bool> HasAsync(Guid accountId, CancellationToken cancellationToken) =>
        Disabled ? Task.FromResult(false) : guardDb.RunAsync(db => db.SecondFactors.AnyAsync(f => f.AccountId == accountId && f.ConfirmedAt != null, cancellationToken),
            cancellationToken: cancellationToken);

    /// <summary>Starts setting up the authenticator app: a new secret, kept until its first code is right.</summary>
    public Task<AppEnrolmentDto> StartAppAsync(Guid accountId, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.AsNoTracking().FirstAsync(a => a.Id == accountId, cancellationToken);
            await db.SecondFactors.Where(f => f.AccountId == accountId && f.Kind == SecondFactorKinds.App && f.ConfirmedAt == null).ExecuteDeleteAsync(cancellationToken);
            byte[] secret = Totp.NewSecret();
            db.SecondFactors.Add(new SecondFactor(Guid.NewGuid(), accountId, SecondFactorKinds.App, Protector.Protect(Totp.ToBase32(secret))));
            await db.SaveChangesAsync(cancellationToken);
            string address = Totp.Address(Issuer, account.Username, secret);
            return new AppEnrolmentDto(Totp.ToBase32(secret), address, QrPng(address));
        }, requiresNew: true, cancellationToken);

    /// <summary>
    /// Finishes setting up the app with its first code. The first second factor comes with ten recovery codes, shown once;
    /// null when the code is wrong.
    /// </summary>
    public async Task<SecondFactorEnrolledDto?> FinishAppAsync(Guid accountId, string? code, CancellationToken cancellationToken)
    {
        SecondFactorEnrolledDto? done = await guardDb.RunAsync<SecondFactorEnrolledDto?>(async db =>
        {
            // The one the code matches: two starts close together (a page loaded twice) can leave two being set up.
            List<SecondFactor> started = await db.SecondFactors
                .Where(f => f.AccountId == accountId && f.Kind == SecondFactorKinds.App && f.ConfirmedAt == null).OrderByDescending(f => f.CreatedAt)
                .ToListAsync(cancellationToken);
            DateTime now = DateTime.UtcNow;
            (SecondFactor? pending, long step) = started
                .Select(f => (f, step: f.ProtectedSecret is { } secret ? Totp.Verify(Totp.FromBase32(Protector.Unprotect(secret)), code, now, 0) : null))
                .Where(x => x.step is not null).Select(x => (x.f, x.step!.Value)).FirstOrDefault();
            if (pending is null)
            {
                return null;
            }

            db.SecondFactors.RemoveRange(started.Where(f => f != pending));
            (pending.ConfirmedAt, pending.LastStep, pending.LastUsedAt) = (now, step, now);
            List<string>? codes = await db.RecoveryCodes.AnyAsync(c => c.AccountId == accountId && c.UsedAt == null, cancellationToken)
                ? null
                : await NewRecoveryCodesAsync(db, accountId, cancellationToken);
            audit.Add(db, SecurityAuditTypes.SecondFactorAdded, new AuditTarget("Account", accountId, null), new { kind = SecondFactorKinds.App });
            await db.SaveChangesAsync(cancellationToken);
            return new SecondFactorEnrolledDto(codes);
        }, requiresNew: true, cancellationToken);
        return done;
    }

    /// <summary>
    /// The account a ticket may set up a second factor for; null when it can't: used, expired, out of tries, or the step
    /// has a method already (the ticket would otherwise pass the step without it). That is the challenge's own rule: only
    /// a person with no factor and no code the site can send them sets one up, so a password alone can't put in an app
    /// in place of the code their email or phone would get.
    /// </summary>
    public Task<Guid?> TicketAccountAsync(string ticket, CancellationToken cancellationToken)
    {
        string hash = Hash(ticket);
        DateTime now = DateTime.UtcNow;
        return guardDb.RunAsync<Guid?>(async db =>
        {
            var row = await db.SignInTickets.AsNoTracking().Where(t => t.TicketHash == hash).Select(t => new { t.AccountId, t.ExpiresAt, t.Attempts, t.ProvedAt })
                .FirstOrDefaultAsync(cancellationToken);
            if (row is null || row.ExpiresAt <= now || row.Attempts >= SignInTicket.MaxAttempts || row.ProvedAt is not null
                || await db.SecondFactors.AnyAsync(f => f.AccountId == row.AccountId && f.ConfirmedAt != null, cancellationToken))
            {
                return null;
            }

            // Sent codes are no SecondFactor rows: where one reaches the person the challenge asked for it, not for enrolment.
            if (await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == row.AccountId, cancellationToken) is not { } account)
            {
                return null;
            }

            bool strong = await ModeAsync(db, account, cancellationToken) == TwoFactorModes.Strong;
            return strong || (await SendersAsync(db, account, cancellationToken)).Count == 0 ? row.AccountId : null;
        }, cancellationToken: cancellationToken);
    }

    /// <summary>A second factor was set up with this ticket: the step is proved, and the next exchange needs no code.</summary>
    public Task ProveTicketAsync(string ticket, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db =>
        {
            string hash = Hash(ticket);
            await db.SignInTickets.Where(t => t.TicketHash == hash).ExecuteUpdateAsync(u => u.SetProperty(t => t.ProvedAt, DateTime.UtcNow), cancellationToken);
        }, requiresNew: true, cancellationToken);

    /// <summary>A wrong code while setting up with a ticket: a try less.</summary>
    public Task SpendTicketTryAsync(string ticket, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db =>
        {
            string hash = Hash(ticket);
            await db.SignInTickets.Where(t => t.TicketHash == hash).ExecuteUpdateAsync(u => u.SetProperty(t => t.Attempts, t => t.Attempts + 1), cancellationToken);
        }, requiresNew: true, cancellationToken);

    public Task<MySecondFactorsDto> ListAsync(Guid accountId, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.AsNoTracking().FirstAsync(a => a.Id == accountId, cancellationToken);
            string mode = await ModeAsync(db, account, cancellationToken);
            List<SecondFactorDto> factors = await db.SecondFactors.AsNoTracking().Where(f => f.AccountId == accountId && f.ConfirmedAt != null)
                .OrderBy(f => f.CreatedAt).Select(f => new SecondFactorDto(f.Id, f.Kind, f.CreatedAt, f.LastUsedAt)).ToListAsync(cancellationToken);
            int left = await db.RecoveryCodes.CountAsync(c => c.AccountId == accountId && c.UsedAt == null, cancellationToken);
            List<SecondFactorSenderDto> senders = Disabled || mode == TwoFactorModes.Strong ? [] : await SendersAsync(db, account, cancellationToken);
            return new MySecondFactorsDto(mode, !Disabled && (TwoFactorModes.Asks(mode) || factors.Count > 0), factors, left, Disabled, senders);
        }, cancellationToken: cancellationToken);

    /// <summary>
    /// The ways the site may send the person a code: each method it allows that reaches them, in the order it
    /// lists them: email to the address their mail goes to, a channel to their verified address on it.
    /// </summary>
    private async Task<List<SecondFactorSenderDto>> SendersAsync(GuardDbContext db, Account account, CancellationToken cancellationToken)
    {
        List<string> allowed = (await Controllers.SecuritySettingsController.LoadAsync(db, cancellationToken)).SecondFactorMethods;
        if (allowed.Count == 0)
        {
            return [];
        }

        // What reaches the person (the messenger's to say: email when mail can go out, a channel where their address is
        // verified), kept to the methods the site allows.
        Dictionary<string, SecondFactorSenderDto> found = [];
        foreach (GuardChannel way in await messenger.ReachAsync(account.Id, account.MailTo ?? account.Email, cancellationToken))
        {
            if (allowed.Contains(way.Method))
            {
                found[way.Method] = new(way.Method, way.Name, way.Method == SecondFactorKinds.Email ? MaskEmail(way.Address) : MaskNumber(way.Address));
            }
        }

        return [.. allowed.Where(found.ContainsKey).Select(m => found[m])];
    }

    /// <summary>Sends a code for a sign-in's second step: the ticket's, for a method that reaches the person.</summary>
    public async Task<SendCodeResult> SendForTicketAsync(string ticket, string? method, string? ip, CancellationToken cancellationToken)
    {
        string hash = Hash(ticket);
        DateTime now = DateTime.UtcNow;
        Guid? accountId = await guardDb.RunAsync(async db => await db.SignInTickets.AsNoTracking().Where(t => t.TicketHash == hash)
            .Select(t => new { t.AccountId, t.ExpiresAt, t.Attempts }).FirstOrDefaultAsync(cancellationToken) is { } row && row.ExpiresAt > now && row.Attempts < SignInTicket.MaxAttempts
            ? row.AccountId
            : (Guid?)null, cancellationToken: cancellationToken);
        return accountId is { } id
            ? await SendAsync(id, method, $"t:{hash[..16]}", ip, cancellationToken)
            : new SendCodeResult(null, "ticket_expired");
    }

    /// <summary>Sends a code to someone signed in, for a step-up.</summary>
    public Task<SendCodeResult> SendForAccountAsync(Guid accountId, string? method, string? ip, CancellationToken cancellationToken) =>
        SendAsync(accountId, method, null, ip, cancellationToken);

    /// <summary>
    /// A new code for the method (six digits, ten minutes, kept as its hash), in place of one sent before, sent as a
    /// secret: the mail log keeps no text of it. Five a person in 15 minutes, three a sign-in.
    /// </summary>
    private async Task<SendCodeResult> SendAsync(Guid accountId, string? method, string? ticketKey, string? ip, CancellationToken cancellationToken)
    {
        if (Disabled || !SecondFactorKinds.IsSent(method))
        {
            return new SendCodeResult(null, "method_not_allowed");
        }

        (SecondFactorSenderDto? sender, string? error, string? username, string? code) = await guardDb.RunAsync<(SecondFactorSenderDto?, string?, string?, string?)>(async db =>
        {
            Account account = await db.Accounts.AsNoTracking().FirstAsync(a => a.Id == accountId, cancellationToken);
            if (!(await Controllers.SecuritySettingsController.LoadAsync(db, cancellationToken)).SecondFactorMethods.Contains(method!)
                || await ModeAsync(db, account, cancellationToken) == TwoFactorModes.Strong)
            {
                return (null, "method_not_allowed", account.Username, null);
            }

            if (await SendersAsync(db, account, cancellationToken) is not { } senders || senders.FirstOrDefault(s => s.Method == method) is not { } found)
            {
                return (null, "unreachable", account.Username, null);
            }

            // Each send is taken from both limits before a code is made, so sends asked for at once can't all go out.
            if (!await limits.TryTakeAsync(SendKey(accountId), MaxSends, WrongCodesWindow, cancellationToken)
                || (ticketKey is not null && !await limits.TryTakeAsync($"second-factor-send|{ticketKey}", MaxSendsPerTicket, SignInTicket.Lifetime, cancellationToken)))
            {
                return (null, "too_many_attempts", account.Username, null);
            }

            string fresh = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
            await db.SentCodes.Where(c => c.AccountId == accountId && c.Method == method).ExecuteDeleteAsync(cancellationToken);
            db.SentCodes.Add(new SentCode(Guid.NewGuid(), accountId, method!, CodeHash(accountId, method!, fresh)));
            await db.SaveChangesAsync(cancellationToken);
            return (found, null, account.Username, fresh);
        }, requiresNew: true, cancellationToken);

        if (sender is null || code is null)
        {
            return new SendCodeResult(null, error);
        }

        // A secret: delivered as rendered, now and once, kept nowhere in the clear, never tried again.
        GuardSendResult result = await messenger.SendAsync(new GuardMessage(
            sender.Method == SecondFactorKinds.Email ? SecondFactorMail.Code : SecondFactorMail.CodeMessage,
            accountId,
            null,
            null,
            new Dictionary<string, object?> { ["code"] = code, ["minutes"] = (int)SentCode.Lifetime.TotalMinutes, ["site"] = Issuer },
            null,
            "second-factor",
            Channel: sender.Method == SecondFactorKinds.Email ? null : sender.Method,
            Secret: true), cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.SecondFactorCodeSent, username, accountId, result.Sent > 0 ? sender.Method : $"{sender.Method}: not sent", ip, cancellationToken);
        return result.Sent > 0
            ? new SendCodeResult(new CodeSentDto(sender.Method, sender.To, DateTime.UtcNow + SentCode.Lifetime), null)
            : new SendCodeResult(null, result.Unreachable > 0 ? "unreachable" : "not_sent");
    }

    private static string SendKey(Guid accountId) => $"second-factor-send|u:{accountId:N}";

    private static string CodeHash(Guid accountId, string method, string code) => Hash($"{accountId:N}|{method}|{code}");

    /// <summary>An address shown so the person knows it, not so others learn it: <c>d•••@example.com</c>.</summary>
    public static string MaskEmail(string address) =>
        address.IndexOf('@') is var at and > 0 ? $"{address[0]}•••{address[at..]}" : "•••";

    /// <summary>A number's last four digits: <c>•••• 1234</c>.</summary>
    public static string MaskNumber(string number)
    {
        string digits = new([.. number.Where(char.IsAsciiDigit)]);
        return digits.Length <= 4 ? "••••" : $"•••• {digits[^4..]}";
    }

    /// <summary>Removes one of the person's second factors; not the last one while a group of theirs requires one.</summary>
    public Task RemoveAsync(Guid accountId, Guid factorId, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db =>
        {
            SecondFactor factor = await db.SecondFactors.FirstOrDefaultAsync(f => f.Id == factorId && f.AccountId == accountId, cancellationToken)
                ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(SecondFactor), factorId);
            Account account = await db.Accounts.AsNoTracking().FirstAsync(a => a.Id == accountId, cancellationToken);
            bool last = !await db.SecondFactors.AnyAsync(f => f.AccountId == accountId && f.Id != factorId && f.ConfirmedAt != null, cancellationToken);
            if (last && TwoFactorModes.Asks(await ModeAsync(db, account, cancellationToken)))
            {
                throw new UserFriendlyException("A group you're in requires a second factor: set up another one before removing this.");
            }

            db.SecondFactors.Remove(factor);
            if (last)
            {
                await db.RecoveryCodes.Where(c => c.AccountId == accountId).ExecuteDeleteAsync(cancellationToken);
            }

            audit.Add(db, SecurityAuditTypes.SecondFactorRemoved, new AuditTarget("Account", accountId, account.Username), new { kind = factor.Kind });
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken);

    /// <summary>Ten new recovery codes in place of the old ones, shown this once.</summary>
    public Task<List<string>> RenewRecoveryCodesAsync(Guid accountId, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db =>
        {
            if (!await db.SecondFactors.AnyAsync(f => f.AccountId == accountId && f.ConfirmedAt != null, cancellationToken))
            {
                throw new UserFriendlyException("Set up a second factor first: recovery codes stand in for it.");
            }

            List<string> codes = await NewRecoveryCodesAsync(db, accountId, cancellationToken);
            audit.Add(db, SecurityAuditTypes.RecoveryCodesRenewed, new AuditTarget("Account", accountId, null));
            await db.SaveChangesAsync(cancellationToken);
            return codes;
        }, requiresNew: true, cancellationToken);

    /// <summary>An admin's reset: every second factor and recovery code of the person goes; their groups may ask them to set one up again.</summary>
    public Task ResetAsync(Guid accountId, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken)
                ?? throw new Volo.Abp.Domain.Entities.EntityNotFoundException(typeof(Account), accountId);
            int removed = await db.SecondFactors.Where(f => f.AccountId == accountId).ExecuteDeleteAsync(cancellationToken);
            await db.RecoveryCodes.Where(c => c.AccountId == accountId).ExecuteDeleteAsync(cancellationToken);
            audit.Add(db, SecurityAuditTypes.SecondFactorReset, new AuditTarget("Account", accountId, account.Username), new { removed });
            await db.SaveChangesAsync(cancellationToken);
            logger.LogInformation("An admin reset the second factors of {Username}", account.Username);
        }, requiresNew: true, cancellationToken);

    /// <summary>A code of the method: one of the person's app factors (each code once), or an unused recovery code (once).</summary>
    private async Task<bool> CheckCodeAsync(GuardDbContext db, Guid accountId, string? method, string? code, bool strong, DateTime now, CancellationToken cancellationToken)
    {
        if (method == SecondFactorKinds.Recovery)
        {
            string hash = Hash(NormalizeRecovery(code));
            // Used once: of two uses at once, only the one whose update finds it still unused.
            return await db.RecoveryCodes.Where(c => c.AccountId == accountId && c.UsedAt == null && c.Hash == hash)
                .ExecuteUpdateAsync(c => c.SetProperty(x => x.UsedAt, now), cancellationToken) > 0;
        }

        // A code sent by email or a channel: the last one for the method, unused, within its ten minutes, while the site
        // still allows the method and no strong group asks for the app.
        if (SecondFactorKinds.IsSent(method))
        {
            if (strong || !(await Controllers.SecuritySettingsController.LoadAsync(db, cancellationToken)).SecondFactorMethods.Contains(method!))
            {
                return false;
            }

            string hash = CodeHash(accountId, method!, new string([.. (code ?? "").Where(char.IsAsciiDigit)]));
            return await db.SentCodes.Where(c => c.AccountId == accountId && c.Method == method && c.UsedAt == null && c.ExpiresAt > now && c.CodeHash == hash)
                .ExecuteUpdateAsync(c => c.SetProperty(x => x.UsedAt, now), cancellationToken) > 0;
        }

        if (method != SecondFactorKinds.App || (strong && !SecondFactorKinds.IsStrong(method)))
        {
            return false;
        }

        foreach (SecondFactor factor in await db.SecondFactors.Where(f => f.AccountId == accountId && f.Kind == SecondFactorKinds.App && f.ConfirmedAt != null)
                     .ToListAsync(cancellationToken))
        {
            // A step passes once: the update finds the factor still before it only for the first of two uses at once.
            if (factor.ProtectedSecret is { } secret && Totp.Verify(Totp.FromBase32(Protector.Unprotect(secret)), code, now, factor.LastStep) is { } step
                && await db.SecondFactors.Where(f => f.Id == factor.Id && f.LastStep < step)
                    .ExecuteUpdateAsync(f => f.SetProperty(x => x.LastStep, step).SetProperty(x => x.LastUsedAt, now), cancellationToken) > 0)
            {
                return true;
            }
        }

        return false;
    }

    private static async Task<List<string>> NewRecoveryCodesAsync(GuardDbContext db, Guid accountId, CancellationToken cancellationToken)
    {
        await db.RecoveryCodes.Where(c => c.AccountId == accountId).ExecuteDeleteAsync(cancellationToken);
        List<string> codes = [];
        for (int i = 0; i < RecoveryCodeCount; i++)
        {
            string code = $"{Block(5)}-{Block(5)}";
            codes.Add(code);
            db.RecoveryCodes.Add(new RecoveryCode(Guid.NewGuid(), accountId, Hash(NormalizeRecovery(code))));
        }

        return codes;
    }

    private static string Block(int length) => new([.. Enumerable.Range(0, length).Select(_ => RecoveryAlphabet[RandomNumberGenerator.GetInt32(RecoveryAlphabet.Length)])]);

    private static string NormalizeRecovery(string? code) => new((code ?? "").ToUpperInvariant().Where(char.IsAsciiLetterOrDigit).ToArray());

    private static string WrongKey(Guid accountId) => $"second-factor|u:{accountId:N}";

    private string Issuer => IssuerFor(options.Value);

    /// <summary>
    /// The authenticator app's issuer: Guard:TwoFactor:Issuer, else the product's English name and the site's host
    /// ("Example (example.com)", say), else the name alone.
    /// </summary>
    public static string IssuerFor(GuardOptions options)
    {
        if (options.TwoFactor.Issuer is { Length: > 0 } issuer)
        {
            return issuer;
        }

        string product = options.Texts.ProductName.TryGetValue("en", out string? english) && english is { Length: > 0 } ? english
            : options.Texts.ProductName.Values.FirstOrDefault(n => n is { Length: > 0 }) ?? GuardMessageTemplates.DefaultProductName;
        return Uri.TryCreate(options.PublicUrl, UriKind.Absolute, out Uri? site) ? $"{product} ({site.Host})" : product;
    }

    private static string QrPng(string text)
    {
        using QRCodeGenerator generator = new();
        using QRCodeData data = generator.CreateQrCode(text, QRCodeGenerator.ECCLevel.Q);
        return "data:image/png;base64," + Convert.ToBase64String(new PngByteQRCode(data).GetGraphic(8));
    }

    private static string Secret() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
