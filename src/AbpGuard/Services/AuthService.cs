using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AbpGuard.Data;
using AbpGuard.Directories;
using AbpGuard.Domain;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>
/// Brute-force limits: 5 failures in 15 minutes for a username from one IP, 50 for a username from anywhere, and 20 for
/// an IP whatever the usernames; each blocks for the rest of its window. Counted per address first, so someone elsewhere
/// can't lock a person out with five wrong passwords; the cap per username still bounds guesses spread over many
/// addresses. Counted for the whole site (<see cref="IGuardRateLimits"/>), so several servers allow no more than one.
/// </summary>
public class LoginRateLimiter(IGuardRateLimits limits) : ISingletonDependency
{
    private const int MaxFailures = 5;
    private const int MaxFailuresFromAnywhere = 50;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);

    public async Task<bool> IsBlockedAsync(string username, string? ip, CancellationToken cancellationToken = default) =>
        await limits.CountAsync(UserAtKey(username, ip), Window, cancellationToken) >= MaxFailures
        || await limits.CountAsync(UserKey(username), Window, cancellationToken) >= MaxFailuresFromAnywhere
        || await IpBlockedAsync(ip, cancellationToken);

    /// <summary>
    /// Takes one of the username's tries, from this IP and from anywhere, before its password is checked; false when
    /// either has none left or the IP is blocked. Taken first, so guesses sent at once can't all be checked before the
    /// first failure counts. A right password gives the tries back (<see cref="ResetAsync"/>).
    /// </summary>
    public async Task<bool> TryBeginAsync(string username, string? ip, CancellationToken cancellationToken = default) =>
        !await IpBlockedAsync(ip, cancellationToken)
        && await limits.TryTakeAsync(UserAtKey(username, ip), MaxFailures, Window, cancellationToken)
        && await limits.TryTakeAsync(UserKey(username), MaxFailuresFromAnywhere, Window, cancellationToken);

    /// <summary>A failure after <see cref="TryBeginAsync"/>, which counted it for the username already: counted for the IP.</summary>
    public async Task RecordFailureAsync(string? ip, CancellationToken cancellationToken = default)
    {
        if (ip is not null)
        {
            await limits.AddAsync(IpKey(ip), cancellationToken);
        }
    }

    private async Task<bool> IpBlockedAsync(string? ip, CancellationToken cancellationToken) =>
        ip is not null && await limits.CountAsync(IpKey(ip), Window, cancellationToken) >= MaxFailures * 4;

    private static string UserKey(string username) => $"sign-in|u:{username}";

    private static string UserAtKey(string username, string? ip) => $"sign-in|u:{username}|ip:{ip}";

    private static string IpKey(string ip) => $"sign-in|ip:{ip}";

    public async Task ResetAsync(string username, string? ip, CancellationToken cancellationToken = default)
    {
        await limits.ResetAsync(UserAtKey(username, ip), cancellationToken);
        await limits.ResetAsync(UserKey(username), cancellationToken);
    }
}

/// <summary>Credential check only. Tokens are issued by the OpenIddict token endpoint.</summary>
/// <summary>MergedInto: the username to sign in with instead, when the account was merged and the password was right.</summary>
public sealed record LoginResult(bool Succeeded, Account? Account, string? ErrorCode, string? MergedInto = null);

/// <summary>
/// A step-up's outcome: whether the password was right, whether the session must end (too many failures), and whether
/// it wasn't checked because the username is blocked for now.
/// </summary>
public sealed record StepUpResult(bool Succeeded, bool EndSession, bool Blocked = false);

public class AuthService(
    GuardDb guardDb,
    ConnectorCatalog connectors,
    LoginRateLimiter limiter) : ITransientDependency
{
    private static readonly PasswordHasher<DirectoryUser> Hasher = new();

    /// <summary>A hash no password matches, checked where there's none of the account's to check (<see cref="Equalize"/>).</summary>
    private static readonly DirectoryUser Nobody = new(Guid.Empty, Guid.Empty, "nobody", "nobody");
    private static readonly string NobodysHash = Hasher.HashPassword(Nobody, Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));

    public static string HashPassword(DirectoryUser user, string password) => Hasher.HashPassword(user, password);

    /// <summary>
    /// Takes as long as checking a password: a sign-in refused before its hash was checked (no such username, an account
    /// that can't sign in) mustn't answer sooner than a wrong password, or its speed tells which usernames exist.
    /// </summary>
    private static void Equalize(string password) => Hasher.VerifyHashedPassword(Nobody, NobodysHash, password);

    public async Task<LoginResult> LoginAsync(string username, string password, string? ip, CancellationToken cancellationToken = default)
    {
        string normalized = GuardConstants.Normalize(username);
        if (!await limiter.TryBeginAsync(normalized, ip, cancellationToken))
        {
            await AuditAsync("auth.login.blocked", normalized, null, "Too many failed attempts", ip, cancellationToken);
            return new LoginResult(false, null, "too_many_attempts");
        }

        (bool ok, Account? account, string reason) = await guardDb.RunAsync<(bool, Account?, string)>(async db =>
        {
            Account? account = await db.Accounts.FirstOrDefaultAsync(a => a.NormalizedUsername == normalized, cancellationToken);
            if (account is null)
            {
                Equalize(password);
                return (false, null, "user_not_found");
            }

            if (account.MergedIntoId is { } survivorId)
            {
                // Merged. Only someone who knows its password learns which account it became.
                return (false, account, await MergedAsync(db, account, survivorId, password, cancellationToken));
            }

            if (account.Status != AccountStatus.Active)
            {
                Equalize(password);
                return (false, account, $"account_{account.Status.ToString().ToLowerInvariant()}");
            }

            // A service account acts only through its tokens.
            if (account.IsService)
            {
                Equalize(password);
                return (false, account, "service_account");
            }

            if (await CheckPasswordAsync(db, account, password, cancellationToken) is { } refused)
            {
                return (false, account, refused);
            }

            account.LastLoginAt = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            return (true, account, "ok");
        }, cancellationToken: cancellationToken);

        if (!ok)
        {
            // The username's try was taken before the check; wrong passwords count for the IP too, account-state failures don't.
            if (reason is "wrong_password" or "user_not_found" or "invalid_credentials")
            {
                await limiter.RecordFailureAsync(ip, cancellationToken);
            }

            await AuditAsync("auth.login.failed", normalized, account?.Id, reason, ip, cancellationToken);
            return reason.StartsWith("account_merged:", StringComparison.Ordinal)
                ? new LoginResult(false, null, "account_merged", reason["account_merged:".Length..])
                : new LoginResult(false, null, "invalid_credentials");
        }

        await limiter.ResetAsync(normalized, ip, cancellationToken);
        await AuditAsync("auth.login.succeeded", normalized, account!.Id, null, ip, cancellationToken);
        return new LoginResult(true, account, null);
    }

    /// <summary>
    /// "account_merged:{survivor}" when the password is the merged account's own; a wrong one is a wrong password, counted
    /// as at any sign-in; otherwise "account_inactive".
    /// </summary>
    private async Task<string> MergedAsync(GuardDbContext db, Account account, Guid survivorId, string password, CancellationToken cancellationToken)
    {
        UserDirectory? directory = await db.Directories.FirstOrDefaultAsync(d => d.Id == account.DirectoryId, cancellationToken);
        DirectoryUser? record = await db.DirectoryUsers.FirstOrDefaultAsync(u => u.DirectoryId == account.DirectoryId && u.NormalizedUsername == account.NormalizedUsername,
            cancellationToken);
        if (directory is not { IsActive: true, AuthenticationEnabled: true } || record is null)
        {
            Equalize(password);
            return "account_inactive";
        }

        if (!(await AuthenticateAsync(directory, record, password)).Succeeded)
        {
            return "wrong_password";
        }

        string? survivor = await db.Accounts.Where(a => a.Id == survivorId).Select(a => a.Username).FirstOrDefaultAsync(cancellationToken);
        return survivor is null ? "account_inactive" : $"account_merged:{survivor}";
    }

    /// <summary>
    /// Step-up: the account's own directory checks the password again, as at sign-in (a hash, or a bind for
    /// LDAP). Failures count toward the sign-in limit; once it's reached, the session ends.
    /// </summary>
    public async Task<StepUpResult> StepUpAsync(Guid accountId, string password, string? ip, CancellationToken cancellationToken = default)
    {
        (Account? account, string? refused) = await guardDb.RunAsync(async db =>
        {
            Account? account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken);
            if (account is null || account.Status != AccountStatus.Active)
            {
                return (account, "account_inactive");
            }

            return (account, !await limiter.TryBeginAsync(account.NormalizedUsername, ip, cancellationToken)
                ? "too_many_attempts"
                : await CheckPasswordAsync(db, account, password, cancellationToken));
        }, cancellationToken: cancellationToken);

        string? username = account?.NormalizedUsername;
        if (refused is null)
        {
            await limiter.ResetAsync(username!, ip, cancellationToken);
            await AuditAsync(SecurityAuditTypes.StepUpSucceeded, username, accountId, null, ip, cancellationToken);
            return new StepUpResult(true, false);
        }

        if (username is not null && refused is "wrong_password" or "invalid_credentials")
        {
            await limiter.RecordFailureAsync(ip, cancellationToken);
        }

        // A wrong password that reaches the limit ends the session; a step-up refused because the name was blocked already
        // (someone else's guesses, maybe) doesn't, or anyone could end a person's session by failing to sign in as them.
        bool end = refused is "account_inactive" or "directory_inactive" or "directory_signin_disabled"
            || (username is not null && refused is "wrong_password" or "invalid_credentials" && await limiter.IsBlockedAsync(username, ip, cancellationToken));
        await AuditAsync(end ? SecurityAuditTypes.StepUpEndedSession : SecurityAuditTypes.StepUpFailed, username, accountId, refused, ip, cancellationToken);
        return new StepUpResult(false, end, refused == "too_many_attempts");
    }

    /// <summary>
    /// The password checked by the directory that owns the account, and only that one: a same-named user in a
    /// lower-priority directory can never sign in as this account. Null when it's right; otherwise why not.
    /// </summary>
    private async Task<string?> CheckPasswordAsync(GuardDbContext db, Account account, string password, CancellationToken cancellationToken)
    {
        UserDirectory? directory = await db.Directories.AsNoTracking().FirstOrDefaultAsync(d => d.Id == account.DirectoryId, cancellationToken);
        DirectoryUser? record = account.DirectoryUserId is { } id ? await db.DirectoryUsers.FindAsync([id], cancellationToken) : null;
        if (directory is null || record is null || !directory.IsActive)
        {
            Equalize(password);
            return "directory_inactive";
        }

        if (!directory.AuthenticationEnabled)
        {
            Equalize(password);
            return "directory_signin_disabled";
        }

        (bool authenticated, string? error) = await AuthenticateAsync(directory, record, password);
        return authenticated ? null : error ?? "wrong_password";
    }

    public async Task<(bool Succeeded, string? Error)> AuthenticateAsync(UserDirectory directory, DirectoryUser record, string password)
    {
        if (directory.IsInternal)
        {
            if (record.PasswordHash is null)
            {
                Equalize(password);
                return (false, "wrong_password");
            }

            bool valid = Hasher.VerifyHashedPassword(record, record.PasswordHash, password) != PasswordVerificationResult.Failed;
            return (valid, valid ? null : "wrong_password");
        }

        return await connectors.WithConnectorAsync(directory.Type, async (connector, _) =>
        {
            if (connector is null)
            {
                return (false, "connector_unavailable");
            }

            ConnectorAuthResult result = await connector.AuthenticateAsync(connectors.BuildContext(directory), record.Username, password, CancellationToken.None);
            return (result.Succeeded, result.Succeeded ? null : result.Error ?? "wrong_password");
        });
    }

    public Task AuditAsync(string type, string? username, Guid? accountId, string? detail, string? ip, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            db.SecurityEvents.Add(new SecurityEvent(Guid.NewGuid(), type, username, accountId, detail, ip));
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken);
}
