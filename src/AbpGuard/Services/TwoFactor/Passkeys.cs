using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using AbpGuard.Data;
using AbpGuard.Domain;
using Volo.Abp;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services.TwoFactor;

/// <summary>The relying party passkeys belong to: its id (the site's domain), the name devices show, and the origins a ceremony may come from.</summary>
public sealed record PasskeyRelyingParty(string Id, string Name, IReadOnlySet<string> Origins);

/// <summary>A passkey registered, or why not: <c>passkey_exists</c> (that device's passkey is registered already) or <c>passkey_rejected</c>.</summary>
public sealed record PasskeyRegistration(Passkey? Passkey, string? Error, string? Why = null);

/// <summary>A passkey's answer checked: the passkey that gave it, or why not (for the security log; the caller answers <c>passkey_rejected</c>).</summary>
public sealed record PasskeyCheck(Passkey? Passkey, string? Why);

/// <summary>
/// Passkeys' WebAuthn ceremonies, with Fido2NetLib: the options for a new passkey (discoverable, with user verification)
/// and for proving with one, and checking the device's answers against them. Every challenge is good once, for five
/// minutes, for the purpose and the session or sign-in ticket that asked (<see cref="PasskeyChallenge"/>); an answer to
/// any other is refused, and so is a signature count that went back. The relying party is the site's address
/// (<see cref="GuardPasskeyOptions"/>). A person's user handle is their account's id: their device's passkey signs in to
/// that account only.
/// </summary>
public sealed class Passkeys(
    GuardDb guardDb,
    IOptions<GuardOptions> options,
    IConfiguration configuration,
    IHostEnvironment environment,
    IHttpContextAccessor http,
    IGuardRateLimits limits,
    ILogger<Passkeys> logger) : ITransientDependency
{
    /// <summary>A challenge's purposes: a passkey added by someone signed in, a step-up, a sign-in's second step, and setting one up at sign-in.</summary>
    public const string Register = "register";
    public const string StepUp = "step-up";
    public const string SecondStep = "second-step";
    public const string Enrol = "enrol";

    /// <summary>The most passkeys a person may have.</summary>
    public const int MaxPerAccount = 20;

    /// <summary>Options asked for, per session or ticket: 20 in five minutes.</summary>
    private const int MaxOptions = 20;

    public const string Exists = "passkey_exists";
    public const string Rejected = "passkey_rejected";

    /// <summary>A web session's challenges belong to it.</summary>
    public static string SessionBinding(Guid sessionId) => $"s:{sessionId:N}";

    /// <summary>An app's sign-in (its OpenIddict permission), for a token that asks.</summary>
    public static string AppBinding(string authorizationId) => $"a:{authorizationId}";

    /// <summary>A sign-in ticket's, by its hash.</summary>
    public static string TicketBinding(string ticketHash) => $"t:{ticketHash}";

    /// <summary>A person's user handle: their account's id, the same on every device.</summary>
    public static byte[] UserHandle(Guid accountId) => accountId.ToByteArray();

    /// <summary>
    /// The relying party as configured: <c>Guard:Passkeys:RpId</c> and <c>Origins</c>, else the site's public address
    /// (<c>Guard:PublicUrl</c>); null when neither says.
    /// </summary>
    public static PasskeyRelyingParty? Resolve(GuardOptions guard, IConfiguration? configuration = null)
    {
        List<string> listed = [.. guard.Passkeys.Origins];
        if (listed.Count == 0 && configuration?["Guard:Passkeys:Origins"] is { Length: > 0 } one)
        {
            listed.Add(one);
        }

        HashSet<string> origins = new(listed.SelectMany(o => o.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Select(o => o.TrimEnd('/')), StringComparer.OrdinalIgnoreCase);
        Uri? site = Uri.TryCreate(guard.PublicUrl, UriKind.Absolute, out Uri? publicUrl) ? publicUrl : null;
        if (origins.Count == 0 && site is not null)
        {
            origins.Add(site.GetLeftPart(UriPartial.Authority));
        }

        string? id = guard.Passkeys.RpId is { Length: > 0 } rpId ? rpId.Trim().ToLowerInvariant()
            : site?.Host ?? origins.Select(o => Uri.TryCreate(o, UriKind.Absolute, out Uri? u) ? u.Host : null).FirstOrDefault(h => h is not null);
        if (id is null || origins.Count == 0)
        {
            return null;
        }

        string name = guard.Passkeys.RpName is { Length: > 0 } rpName ? rpName : guard.Texts.Product();
        return new PasskeyRelyingParty(id, name, origins);
    }

    /// <summary>
    /// The relying party; in Development with none configured, the request's own address. Elsewhere unset is an error
    /// that says what to set: a passkey made for a guessed address would stop working when the guess changes.
    /// </summary>
    public PasskeyRelyingParty RelyingParty()
    {
        if (Resolve(options.Value, configuration) is { } configured)
        {
            return configured;
        }

        if (environment.IsDevelopment() && http.HttpContext?.Request is { } request)
        {
            string origin = $"{request.Scheme}://{request.Host}";
            return new PasskeyRelyingParty(request.Host.Host, options.Value.Texts.Product(), new HashSet<string>(StringComparer.OrdinalIgnoreCase) { origin });
        }

        throw new InvalidOperationException("Passkeys need the site's address: set Guard:PublicUrl, or Guard:Passkeys:RpId and Guard:Passkeys:Origins "
            + "(environment Guard__Passkeys__RpId and Guard__Passkeys__Origins).");
    }

    private Fido2 Fido(PasskeyRelyingParty rp) => new(new Fido2Configuration
    {
        RPID = rp.Id,
        RPName = rp.Name,
        Origins = rp.Origins,
        ChallengeSize = 32,
        Timeout = (uint)PasskeyChallenge.Lifetime.TotalMilliseconds,
    });

    /// <summary>
    /// The options for a new passkey of the account (the browser's <c>PublicKeyCredentialCreationOptionsJSON</c>):
    /// discoverable, with user verification, no attestation asked, and the person's passkeys excluded.
    /// </summary>
    public async Task<string> CreationOptionsAsync(Guid accountId, string purpose, string binding, CancellationToken cancellationToken)
    {
        await LimitAsync(binding, cancellationToken);
        PasskeyRelyingParty rp = RelyingParty();
        return await guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.AsNoTracking().FirstAsync(a => a.Id == accountId, cancellationToken);
            List<Passkey> mine = await db.Passkeys.AsNoTracking().Where(p => p.AccountId == accountId).ToListAsync(cancellationToken);
            CredentialCreateOptions created = Fido(rp).RequestNewCredential(new RequestNewCredentialParams
            {
                User = new Fido2User { Id = UserHandle(accountId), Name = account.Username, DisplayName = account.DisplayName },
                ExcludeCredentials = [.. mine.Select(Descriptor)],
                AuthenticatorSelection = new AuthenticatorSelection { ResidentKey = ResidentKeyRequirement.Required, UserVerification = UserVerificationRequirement.Required },
                AttestationPreference = AttestationConveyancePreference.None,
                PubKeyCredParams = [PubKeyCredParam.ES256, PubKeyCredParam.Ed25519, PubKeyCredParam.RS256, PubKeyCredParam.PS256, PubKeyCredParam.ES384, PubKeyCredParam.ES512],
            });
            string json = created.ToJson();
            await KeepAsync(db, accountId, created.Challenge, purpose, binding, json, cancellationToken);
            return json;
        }, requiresNew: true, cancellationToken);
    }

    /// <summary>
    /// The options for proving with one of the account's passkeys (the browser's <c>PublicKeyCredentialRequestOptionsJSON</c>),
    /// with user verification; null when the person has none.
    /// </summary>
    public async Task<string?> RequestOptionsAsync(Guid accountId, string purpose, string binding, CancellationToken cancellationToken)
    {
        await LimitAsync(binding, cancellationToken);
        PasskeyRelyingParty rp = RelyingParty();
        return await guardDb.RunAsync<string?>(async db =>
        {
            List<Passkey> mine = await db.Passkeys.AsNoTracking().Where(p => p.AccountId == accountId).OrderByDescending(p => p.LastUsedAt).ToListAsync(cancellationToken);
            if (mine.Count == 0)
            {
                return null;
            }

            AssertionOptions asked = Fido(rp).GetAssertionOptions(new GetAssertionOptionsParams
            {
                AllowedCredentials = [.. mine.Select(Descriptor)],
                UserVerification = UserVerificationRequirement.Required,
            });
            string json = asked.ToJson();
            await KeepAsync(db, accountId, asked.Challenge, purpose, binding, json, cancellationToken);
            return json;
        }, requiresNew: true, cancellationToken);
    }

    /// <summary>
    /// Checks the device's answer to creation options (the credential's <c>toJSON()</c>) and adds the passkey, in the
    /// caller's unit of work; it isn't saved until the caller saves. Refused when the challenge isn't this purpose's and
    /// binding's, is used or older than five minutes, or the answer doesn't verify (origin, relying party, user
    /// verification, signature).
    /// </summary>
    public async Task<PasskeyRegistration> RegisterAsync(GuardDbContext db, Guid accountId, string purpose, string binding, string? name, JsonElement? credential,
        CancellationToken cancellationToken)
    {
        if (Read<AuthenticatorAttestationRawResponse>(credential) is not { Response: { } response } raw)
        {
            return new(null, Rejected, "no answer");
        }

        if (await TakeAsync(db, accountId, purpose, binding, response.ClientDataJson, cancellationToken) is not { } options)
        {
            return new(null, Rejected, "challenge");
        }

        if (await db.Passkeys.CountAsync(p => p.AccountId == accountId, cancellationToken) >= MaxPerAccount)
        {
            throw new UserFriendlyException($"You have {MaxPerAccount} passkeys: remove one before adding another.");
        }

        RegisteredPublicKeyCredential made;
        try
        {
            made = await Fido(RelyingParty()).MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = raw,
                OriginalOptions = CredentialCreateOptions.FromJson(options),
                // One credential id site-wide: a device's passkey belongs to one account.
                IsCredentialIdUniqueToUserCallback = async (args, ct) => !await db.Passkeys.AnyAsync(p => p.CredentialId == args.CredentialId, ct),
            }, cancellationToken);
        }
        catch (Fido2VerificationException ex) when (ex.Code == Fido2ErrorCode.NonUniqueCredentialId)
        {
            return new(null, Exists);
        }
        catch (Exception ex) when (ex is Fido2VerificationException or JsonException or FormatException or ArgumentException or InvalidOperationException)
        {
            logger.LogInformation("A passkey's registration was refused: {Why}", ex.Message);
            return new(null, Rejected, ex.Message);
        }

        string given = (name ?? "").Trim();
        Passkey passkey = new(Guid.NewGuid(), accountId, made.Id, made.PublicKey, made.SignCount, made.AaGuid, Transports(made.Transports), made.IsBackupEligible,
            made.IsBackedUp, given.Length > 0 ? given[..Math.Min(given.Length, Passkey.NameLength)] : PasskeyProviders.Name(made.AaGuid) ?? "Passkey");
        db.Passkeys.Add(passkey);
        return new(passkey, null);
    }

    /// <summary>
    /// Checks the device's answer to request options in the caller's unit of work: the account's passkey that gave it, its
    /// signature count moved on (a count that didn't, or went back, is refused: a copied passkey), and when it was used.
    /// </summary>
    public async Task<PasskeyCheck> VerifyAsync(GuardDbContext db, Guid accountId, string purpose, string binding, JsonElement? credential, CancellationToken cancellationToken)
    {
        if (Read<AuthenticatorAssertionRawResponse>(credential) is not { Response: { } response, RawId: { } rawId } raw)
        {
            return new(null, "no answer");
        }

        if (await TakeAsync(db, accountId, purpose, binding, response.ClientDataJson, cancellationToken) is not { } options)
        {
            return new(null, "challenge");
        }

        Passkey? key = await db.Passkeys.AsNoTracking().FirstOrDefaultAsync(p => p.AccountId == accountId && p.CredentialId == rawId, cancellationToken);
        if (key is null)
        {
            return new(null, "not the person's passkey");
        }

        VerifyAssertionResult proved;
        byte[] handle = UserHandle(accountId);
        try
        {
            proved = await Fido(RelyingParty()).MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = raw,
                OriginalOptions = AssertionOptions.FromJson(options),
                StoredPublicKey = key.PublicKey,
                StoredSignatureCounter = (uint)key.SignCount,
                IsUserHandleOwnerOfCredentialIdCallback = (args, _) => Task.FromResult(args.UserHandle.AsSpan().SequenceEqual(handle)
                    && args.CredentialId.AsSpan().SequenceEqual(key.CredentialId)),
            }, cancellationToken);
        }
        catch (Exception ex) when (ex is Fido2VerificationException or JsonException or FormatException or ArgumentException or InvalidOperationException)
        {
            logger.LogInformation("A passkey's answer was refused: {Why}", ex.Message);
            return new(null, ex is Fido2VerificationException { Code: Fido2ErrorCode.InvalidSignCount } ? "sign count went back" : ex.Message);
        }

        // The count moves on from the one read, once: of two answers at once, only the first.
        DateTime now = DateTime.UtcNow;
        long before = key.SignCount;
        if (await db.Passkeys.Where(p => p.Id == key.Id && p.SignCount == before).ExecuteUpdateAsync(set => set
                .SetProperty(p => p.SignCount, (long)proved.SignCount)
                .SetProperty(p => p.BackedUp, proved.IsBackedUp)
                .SetProperty(p => p.LastUsedAt, now), cancellationToken) == 0)
        {
            return new(null, "sign count went back");
        }

        (key.SignCount, key.BackedUp, key.LastUsedAt) = (proved.SignCount, proved.IsBackedUp, now);
        return new(key, null);
    }

    /// <summary>The account's passkeys, oldest first.</summary>
    public static Task<List<Passkey>> OfAsync(GuardDbContext db, Guid accountId, CancellationToken cancellationToken) =>
        db.Passkeys.AsNoTracking().Where(p => p.AccountId == accountId).OrderBy(p => p.CreatedAt).ToListAsync(cancellationToken);

    /// <summary>Keeps a challenge for its purpose and binding; old ones go.</summary>
    private static async Task KeepAsync(GuardDbContext db, Guid accountId, byte[] challenge, string purpose, string binding, string json, CancellationToken cancellationToken)
    {
        DateTime now = DateTime.UtcNow;
        await db.PasskeyChallenges.Where(c => c.ExpiresAt < now).ExecuteDeleteAsync(cancellationToken);
        db.PasskeyChallenges.Add(new PasskeyChallenge(Guid.NewGuid(), accountId, HashOf(challenge), purpose, binding, json));
        await db.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Takes the challenge an answer's client data names, once, when it's this account's, purpose's and binding's: the
    /// options it was sent with, or null (unknown, someone else's, used, or older than five minutes).
    /// </summary>
    private static async Task<string?> TakeAsync(GuardDbContext db, Guid accountId, string purpose, string binding, byte[]? clientDataJson, CancellationToken cancellationToken)
    {
        if (ChallengeOf(clientDataJson) is not { } challenge)
        {
            return null;
        }

        string hash = HashOf(challenge);
        PasskeyChallenge? row = await db.PasskeyChallenges.AsNoTracking()
            .FirstOrDefaultAsync(c => c.ChallengeHash == hash && c.AccountId == accountId && c.Purpose == purpose && c.Binding == binding, cancellationToken);
        // Good once: of two answers at once, only the one that removes it.
        if (row is null || await db.PasskeyChallenges.Where(c => c.Id == row.Id).ExecuteDeleteAsync(cancellationToken) == 0)
        {
            return null;
        }

        return row.ExpiresAt > DateTime.UtcNow ? row.Options : null;
    }

    /// <summary>The challenge the client data says it answers, or null when it doesn't read.</summary>
    public static byte[]? ChallengeOf(byte[]? clientDataJson)
    {
        if (clientDataJson is not { Length: > 0 })
        {
            return null;
        }

        try
        {
            using JsonDocument data = JsonDocument.Parse(clientDataJson);
            return data.RootElement.ValueKind == JsonValueKind.Object && data.RootElement.TryGetProperty("challenge", out JsonElement value)
                && value.ValueKind == JsonValueKind.String && value.GetString() is { Length: > 0 } text
                ? Base64Url.DecodeFromChars(text)
                : null;
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            return null;
        }
    }

    private static string HashOf(byte[] challenge) => Convert.ToHexStringLower(SHA256.HashData(challenge));

    private async Task LimitAsync(string binding, CancellationToken cancellationToken)
    {
        if (!await limits.TryTakeAsync($"passkey-options|{binding}", MaxOptions, PasskeyChallenge.Lifetime, cancellationToken))
        {
            throw new UserFriendlyException("Too many tries. Try again in a few minutes.", GuardErrorCodes.TooManyRequests);
        }
    }

    private static T? Read<T>(JsonElement? credential) where T : class
    {
        if (credential is not { ValueKind: JsonValueKind.Object } element)
        {
            return null;
        }

        try
        {
            return element.Deserialize<T>();
        }
        catch (Exception ex) when (ex is JsonException or FormatException or NotSupportedException or ArgumentException)
        {
            return null;
        }
    }

    private static PublicKeyCredentialDescriptor Descriptor(Passkey passkey) =>
        new(PublicKeyCredentialType.PublicKey, passkey.CredentialId, TransportsOf(passkey.Transports) is { Length: > 0 } transports ? transports : null);

    private static readonly (AuthenticatorTransport Transport, string Name)[] TransportNames =
    [
        (AuthenticatorTransport.Usb, "usb"), (AuthenticatorTransport.Nfc, "nfc"), (AuthenticatorTransport.Ble, "ble"),
        (AuthenticatorTransport.SmartCard, "smart-card"), (AuthenticatorTransport.Hybrid, "hybrid"), (AuthenticatorTransport.Internal, "internal"),
    ];

    private static string? Transports(AuthenticatorTransport[]? transports) =>
        transports is { Length: > 0 } ? string.Join(',', transports.Distinct().Select(t => TransportNames.First(n => n.Transport == t).Name)) : null;

    private static AuthenticatorTransport[] TransportsOf(string? transports) =>
        [.. (transports ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries).SelectMany(name => TransportNames.Where(n => n.Name == name).Select(n => n.Transport))];
}
