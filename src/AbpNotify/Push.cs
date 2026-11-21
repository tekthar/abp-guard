using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AbpConnections;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Volo.Abp;
using Volo.Abp.DependencyInjection;
using Volo.Abp.Domain.Entities;

namespace AbpNotify;

// Push to phones: the FCM connection kind and client, the push channel, and people's phones. What a push says, and
// what the app reads in it, is the application's (IPushMessages; PlainPushMessages without one).

/// <summary>
/// Firebase Cloud Messaging: a Firebase project's service account, whose key signs the application in to Google to
/// send pushes to its app. The addresses are Google's unless a test points elsewhere; the project is the key's unless
/// named.
/// </summary>
[ExposeServices(typeof(IConnectionKind), typeof(FcmConnectionKind))]
public sealed class FcmConnectionKind(IOptions<NotifyOptions> options) : IConnectionKind, ITransientDependency
{
    public const string Key = "fcm";

    public string Type => Key;

    public string DisplayName => "Firebase Cloud Messaging (push)";

    public bool SignsIn => false;

    public IReadOnlyList<ConnectionSetting> Settings { get; } =
    [
        new("apiUrl", "API address", DefaultValue: FcmAccount.DefaultApi),
        new("tokenUrl", "Token address", Help: "Blank: the key's own (its token_uri)."),
        new("projectId", "Firebase project id", Help: "Blank: the key's own (its project_id)."),
        new("serviceAccount", "Service account key", Secret: true, Required: true,
            Help: "The JSON key of a service account that may send messages (Firebase console › Project settings › Service accounts › Generate new private key)."),
    ];

    public ConnectionOAuthSetup? OAuth(IReadOnlyDictionary<string, string> settings, IReadOnlyDictionary<string, string> secrets) => null;

    /// <summary>Signs in to Google with the key (a push needs a phone to go to, so none is sent).</summary>
    public async Task<ConnectionTestResult> TestAsync(ConnectionInUse connection, HttpClient http, CancellationToken cancellationToken)
    {
        FcmAccount account = FcmAccount.From(connection);
        await FcmClient.MintAsync(http, account, DateTimeOffset.UtcNow, cancellationToken, options.Value.ApplicationName);
        return new ConnectionTestResult(true, $"Signed in to Google as {account.ClientEmail}, for the Firebase project {account.ProjectId}.", account.ClientEmail);
    }
}

/// <summary>
/// A Firebase service account as pushes are sent with it: who it is, its key, where it gets tokens, and the project and
/// API it sends to. Fingerprint tells a key apart from the one it replaced, so a token minted with the old one isn't used.
/// </summary>
public sealed record FcmAccount(Guid ConnectionId, string ClientEmail, string PrivateKey, string? KeyId, string TokenUrl, string ProjectId, string ApiUrl, string Fingerprint)
{
    public const string DefaultApi = "https://fcm.googleapis.com";
    public const string DefaultTokenUrl = "https://oauth2.googleapis.com/token";
    public const string Scope = "https://www.googleapis.com/auth/firebase.messaging";

    /// <summary>The account in a connection's key and settings; a key that isn't one is said plainly.</summary>
    public static FcmAccount From(ConnectionInUse connection)
    {
        string json = connection.Secrets.GetValueOrDefault("serviceAccount") ?? "";
        JsonObject key;
        try
        {
            key = JsonNode.Parse(json) as JsonObject ?? throw new UserFriendlyException("The service account key isn't a JSON object.");
        }
        catch (JsonException)
        {
            throw new UserFriendlyException("The service account key isn't JSON: paste the whole file Firebase gave you.");
        }

        string? Read(string name) => key[name] is JsonValue v && v.TryGetValue(out string? s) && !string.IsNullOrWhiteSpace(s) ? s.Trim() : null;
        string? Setting(string name) => connection.Settings.GetValueOrDefault(name) is { Length: > 0 } s ? s.Trim() : null;
        string email = Read("client_email") ?? throw new UserFriendlyException("The service account key has no client_email.");
        string privateKey = Read("private_key") ?? throw new UserFriendlyException("The service account key has no private_key.");
        string project = Setting("projectId") ?? Read("project_id") ?? throw new UserFriendlyException("Name the Firebase project: the key has no project_id.");
        string tokenUrl = Setting("tokenUrl") ?? Read("token_uri") ?? DefaultTokenUrl;
        string api = (Setting("apiUrl") ?? DefaultApi).TrimEnd('/');
        string fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{json}\n{tokenUrl}")))[..16];
        return new FcmAccount(connection.Id, email, privateKey, Read("private_key_id"), tokenUrl, project, api, fingerprint);
    }

    /// <summary>
    /// The signed statement Google trades for an access token (OAuth 2.0's JWT bearer grant): the service account asks,
    /// for sending messages, of the token address, for an hour; signed with its key (RS256). <paramref name="application"/>
    /// is what a key it can't read is said to be unreadable by.
    /// </summary>
    public string Assertion(DateTimeOffset now, string application = "this server")
    {
        JsonObject header = new() { ["alg"] = "RS256", ["typ"] = "JWT" };
        if (KeyId is not null)
        {
            header["kid"] = KeyId;
        }

        long issued = now.ToUnixTimeSeconds();
        JsonObject claims = new() { ["iss"] = ClientEmail, ["scope"] = Scope, ["aud"] = TokenUrl, ["iat"] = issued, ["exp"] = issued + 3600 };
        string signed = $"{Base64Url(Encoding.UTF8.GetBytes(header.ToJsonString()))}.{Base64Url(Encoding.UTF8.GetBytes(claims.ToJsonString()))}";
        using RSA rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(PrivateKey);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            throw new UserFriendlyException($"The service account's private_key isn't a key {application} can read.");
        }

        byte[] signature = rsa.SignData(Encoding.ASCII.GetBytes(signed), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{signed}.{Base64Url(signature)}";
    }

    internal static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>What became of one push: sent, the phone gone for good, the token refused, worth trying again, or refused for another reason.</summary>
public enum FcmResult
{
    Sent,
    Dead,
    Unauthorized,
    Transient,
    Refused,
}

public sealed record FcmOutcome(FcmResult Result, string? Error = null)
{
    public static readonly FcmOutcome Sent = new(FcmResult.Sent);

    /// <summary>
    /// What an answer of FCM's HTTP v1 API means. A phone is gone when FCM says the token is unregistered, isn't a
    /// token, or belongs to another sender: never for an error about the message or the project, so a mistake there
    /// doesn't forget everyone's phones. Its access token refused, the client signs in again; busy or failing, later.
    /// </summary>
    public static FcmOutcome Classify(int status, string body)
    {
        if (status is >= 200 and < 300)
        {
            return Sent;
        }

        JsonObject? error = null;
        try
        {
            error = (JsonNode.Parse(body) as JsonObject)?["error"] as JsonObject;
        }
        catch (JsonException)
        {
            // not JSON: the status says it
        }

        string message = error?["message"] is JsonValue m && m.TryGetValue(out string? text) ? text : $"FCM answered {status}.";
        List<string> codes = [];
        List<string> fields = [];
        foreach (JsonObject detail in (error?["details"] as JsonArray ?? []).OfType<JsonObject>())
        {
            if (detail["errorCode"] is JsonValue code && code.TryGetValue(out string? c))
            {
                codes.Add(c);
            }

            foreach (JsonObject violation in (detail["fieldViolations"] as JsonArray ?? []).OfType<JsonObject>())
            {
                if (violation["field"] is JsonValue field && field.TryGetValue(out string? f))
                {
                    fields.Add(f);
                }
            }
        }

        string why = $"FCM answered {status}: {message}";
        bool aboutToken = fields.Contains("message.token") || message.Contains("registration token", StringComparison.OrdinalIgnoreCase);
        return status switch
        {
            404 when codes.Contains("UNREGISTERED") => new FcmOutcome(FcmResult.Dead, why),
            400 when aboutToken && (codes.Contains("INVALID_ARGUMENT") || codes.Count == 0) => new FcmOutcome(FcmResult.Dead, why),
            403 when codes.Contains("SENDER_ID_MISMATCH") => new FcmOutcome(FcmResult.Dead, why),
            401 => new FcmOutcome(FcmResult.Unauthorized, why),
            429 or >= 500 => new FcmOutcome(FcmResult.Transient, why),
            _ => new FcmOutcome(FcmResult.Refused, why),
        };
    }
}

/// <summary>
/// Sends pushes through FCM's HTTP v1 API, signed in with a connection's service account: an access token is minted
/// from the key and kept until five minutes before it expires, one per connection and key, so a burst of notices signs
/// in once. Calls go through the application's guarded client (<see cref="NotifyOptions.HttpClientName"/>).
/// </summary>
public sealed class FcmClient(IHttpClientFactory clients, ILogger<FcmClient> logger, IOptions<NotifyOptions> options) : ISingletonDependency
{
    private static readonly TimeSpan Margin = TimeSpan.FromMinutes(5);
    private readonly ConcurrentDictionary<string, (string Token, DateTimeOffset ExpiresAt)> _tokens = new();
    private readonly SemaphoreSlim _minting = new(1, 1);

    /// <summary>Sends one message (its <c>token</c> names the phone); a refused access token is minted again and the send tried once more.</summary>
    public async Task<FcmOutcome> SendAsync(FcmAccount account, JsonObject message, CancellationToken ct)
    {
        HttpClient http = clients.CreateClient(options.Value.HttpClientName);
        for (int attempt = 0; ; attempt++)
        {
            string access;
            try
            {
                access = await AccessAsync(http, account, ct);
            }
            catch (ProviderTroubleException ex)
            {
                return new FcmOutcome(FcmResult.Transient, ex.Message);
            }

            using HttpRequestMessage request = new(HttpMethod.Post, $"{account.ApiUrl}/v1/projects/{Uri.EscapeDataString(account.ProjectId)}/messages:send")
            {
                Content = new StringContent(new JsonObject { ["message"] = message.DeepClone() }.ToJsonString(), Encoding.UTF8, "application/json"),
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
            FcmOutcome outcome;
            try
            {
                using HttpResponseMessage response = await http.SendAsync(request, ct);
                outcome = FcmOutcome.Classify((int)response.StatusCode, await response.Content.ReadAsStringAsync(ct));
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
            {
                return new FcmOutcome(FcmResult.Transient, $"FCM didn't answer: {ex.Message}");
            }

            if (outcome.Result != FcmResult.Unauthorized || attempt > 0)
            {
                return outcome;
            }

            logger.LogInformation("FCM refused the access token of connection {Connection}; signing in again.", account.ConnectionId);
            _tokens.TryRemove(CacheKey(account), out _);
        }
    }

    /// <summary>The account's access token: the one kept while it has more than five minutes left, else a new one.</summary>
    private async Task<string> AccessAsync(HttpClient http, FcmAccount account, CancellationToken ct)
    {
        string key = CacheKey(account);
        if (_tokens.TryGetValue(key, out var kept) && kept.ExpiresAt - DateTimeOffset.UtcNow > Margin)
        {
            return kept.Token;
        }

        await _minting.WaitAsync(ct);
        try
        {
            if (_tokens.TryGetValue(key, out kept) && kept.ExpiresAt - DateTimeOffset.UtcNow > Margin)
            {
                return kept.Token; // another send minted it while this one waited
            }

            (string token, DateTimeOffset expires) = await MintAsync(http, account, DateTimeOffset.UtcNow, ct, options.Value.ApplicationName);
            _tokens[key] = (token, expires);
            return token;
        }
        catch (UserFriendlyException ex)
        {
            throw new ProviderTroubleException(ex.Message);
        }
        finally
        {
            _minting.Release();
        }
    }

    /// <summary>Trades the account's signed statement for an access token at its token address.</summary>
    public static async Task<(string Token, DateTimeOffset ExpiresAt)> MintAsync(HttpClient http, FcmAccount account, DateTimeOffset now, CancellationToken ct,
        string application = "this server")
    {
        using HttpRequestMessage request = new(HttpMethod.Post, account.TokenUrl)
        {
            Content = new FormUrlEncodedContent([
                KeyValuePair.Create("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"), KeyValuePair.Create("assertion", account.Assertion(now, application))]),
        };
        string body;
        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request, ct);
            body = await response.Content.ReadAsStringAsync(ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            throw new UserFriendlyException($"Google's token address didn't answer: {ex.Message}");
        }

        using HttpResponseMessage answered = response;
        JsonObject? json = null;
        try
        {
            json = JsonNode.Parse(body) as JsonObject;
        }
        catch (JsonException)
        {
            // not JSON: said below
        }

        if (!response.IsSuccessStatusCode || json?["access_token"] is not JsonValue value || !value.TryGetValue(out string? token) || string.IsNullOrEmpty(token))
        {
            string why = (json?["error_description"] ?? json?["error"])?.ToString() ?? $"{(int)response.StatusCode} {response.ReasonPhrase}";
            throw new UserFriendlyException($"Google refused the service account: {why}");
        }

        long seconds = json["expires_in"] is { } e && long.TryParse(e.ToString(), out long s) ? s : 3600;
        return (token, now.AddSeconds(seconds));
    }

    private static string CacheKey(FcmAccount account) => $"{account.ConnectionId:N}:{account.Fingerprint}";

    /// <summary>Signing in failed: the push waits, as it would for FCM being busy.</summary>
    private sealed class ProviderTroubleException(string message) : Exception(message);
}

/// <summary>What a push says and carries for the application's app, from a message rendered for one phone.</summary>
public interface IPushMessages
{
    /// <summary>The FCM message to the phone with this token.</summary>
    JsonObject Message(NotifyDelivery delivery, string token);
}

/// <summary>
/// Pushes to people's phones: a person's notices go to every phone they registered in the application's app, through
/// the site's FCM connection. A person is reached once they've a phone registered; with none, they're unreachable here
/// and hear by mail. The address is the person (their account), so a retry finds their phones as they are then.
/// </summary>
[ExposeServices(typeof(INotifyChannel), typeof(PushChannel))]
public sealed class PushChannel(ConnectionManager connections, DeviceBook devices, FcmClient fcm, IPushMessages messages, ILogger<PushChannel> logger)
    : INotifyChannel, IPersonalNotifyChannel, ITransientDependency
{
    public const string ChannelKey = "push";

    public string Key => ChannelKey;

    public IReadOnlyList<string> Kinds { get; } = [NotifyTemplateKinds.Message];

    public string Name => "Phone (push)";

    public bool PeopleTypeAddress => false;

    public string? AddressHint => null;

    public string? Normalize(string address) => null;

    public async Task<bool> ReadyAsync(CancellationToken cancellationToken) => await SiteConnectionAsync(cancellationToken) is not null;

    public bool IsAddress(string address) => Guid.TryParse(address, out _);

    public async Task<string?> AddressAsync(NotifyPerson person, CancellationToken cancellationToken) =>
        await devices.AnyAsync(person.Id, cancellationToken) ? person.Id.ToString() : null;

    /// <summary>
    /// To each of the person's phones. A phone FCM says is gone is forgotten. Throws, so the message is tried again later,
    /// only when no phone took it and one may yet (FCM busy, failing, or refusing for a reason a site admin can fix).
    /// </summary>
    public async Task DeliverAsync(NotifyDelivery delivery, CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(delivery.Address, out Guid accountId))
        {
            throw new InvalidOperationException($"{delivery.Address} isn't a person to push to.");
        }

        ConnectionInUse connection = await SiteConnectionAsync(cancellationToken) is { } site && await connections.GetForUseAsync(site.Id, cancellationToken) is { } found
            ? found
            : throw new InvalidOperationException("Push isn't set up on this site: it has no Firebase Cloud Messaging connection.");
        FcmAccount account = FcmAccount.From(connection);
        List<string> tokens = await devices.TokensAsync(accountId, cancellationToken);
        if (tokens.Count == 0)
        {
            logger.LogInformation("Message {Id}: {Account} has no phone registered now; it's in their inbox.", delivery.Id, accountId);
            return;
        }

        int sent = 0;
        List<string> failures = [];
        foreach (string token in tokens)
        {
            FcmOutcome outcome = await fcm.SendAsync(account, messages.Message(delivery, token), cancellationToken);
            switch (outcome.Result)
            {
                case FcmResult.Sent:
                    sent++;
                    break;
                case FcmResult.Dead:
                    logger.LogInformation("Message {Id}: a phone of {Account} is gone ({Error}); it's forgotten.", delivery.Id, accountId, outcome.Error);
                    await devices.DropAsync(token, cancellationToken);
                    break;
                default:
                    failures.Add(outcome.Error ?? outcome.Result.ToString());
                    break;
            }
        }

        if (sent == 0 && failures.Count > 0)
        {
            throw new InvalidOperationException(string.Join(" ", failures.Distinct()));
        }
    }

    private async Task<ConnectionSummaryView?> SiteConnectionAsync(CancellationToken cancellationToken) =>
        (await connections.ListOfTypeAsync(FcmConnectionKind.Key, null, cancellationToken)).Where(c => c.ScopeId is null).OrderBy(c => c.Name).FirstOrDefault();
}

/// <summary>A phone as its person sees it: never its token.</summary>
public sealed record DeviceDto(Guid Id, string Platform, string Name, DateTime CreatedAt, DateTime LastSeenAt);

/// <summary>A phone to register: its push token, android or ios, and what it calls itself.</summary>
public sealed record DeviceInput(string? Token, string? Platform, string? Name);

/// <summary>
/// People's phones. The app registers its phone on every start (the same token again only says it's still there); a
/// person with a phone registered has a verified address on the push channel, so they may choose it, and with none
/// left they hear by mail again. A person keeps at most ten: an eleventh drops the one seen longest ago.
/// </summary>
public sealed class DeviceBook(IServiceScopeFactory scopes, INotifyAddresses addresses, IOptions<NotifyOptions> options) : ITransientDependency
{
    public const int MaxPerPerson = 10;
    public const int MaxToken = PersonDevice.MaxToken;
    public const int MaxName = PersonDevice.MaxName;

    public async Task<List<DeviceDto>> MineAsync(Guid me, CancellationToken ct)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().Devices.AsNoTracking().Where(d => d.AccountId == me)
            .OrderByDescending(d => d.LastSeenAt).Select(d => new DeviceDto(d.Id, d.Platform, d.Name, d.CreatedAt, d.LastSeenAt)).ToListAsync(ct);
    }

    /// <summary>
    /// Registers a phone, or says it's still there. A token another account registered moves to this one: whoever
    /// signed in on the phone last is who it's for.
    /// </summary>
    public async Task<DeviceDto> RegisterAsync(Guid me, DeviceInput input, CancellationToken ct)
    {
        string token = (input.Token ?? "").Trim();
        if (token.Length is 0 or > MaxToken)
        {
            throw new UserFriendlyException($"A phone's push token is 1 to {MaxToken} characters.");
        }

        string platform = (input.Platform ?? "").Trim().ToLowerInvariant();
        if (!DevicePlatforms.All.Contains(platform))
        {
            throw new UserFriendlyException(platform.Length == 0
                ? $"Say whether the phone is {string.Join(" or ", DevicePlatforms.All)}."
                : $"A phone is {string.Join(" or ", DevicePlatforms.All)}; not \"{input.Platform}\".");
        }

        string name = (input.Name ?? "").Trim();
        name = name.Length == 0 ? (platform == DevicePlatforms.Ios ? "iPhone" : "Android phone") : name[..Math.Min(name.Length, MaxName)];

        Guid? before;
        PersonDevice device;
        await using (AsyncServiceScope scope = scopes.CreateAsyncScope())
        {
            INotifyDbContext db = scope.ServiceProvider.GetRequiredService<INotifyDbContext>();
            before = await db.Devices.AsNoTracking().Where(d => d.Token == token).Select(d => (Guid?)d.AccountId).FirstOrDefaultAsync(ct);
            DateTime now = DateTime.UtcNow;
            // One statement, so two starts of the app at once can't both insert the token.
            NotifyTable t = NotifyTable.Of<PersonDevice>(db);
            (string account, string platformColumn, string nameColumn, string seen, string created) = (t[nameof(PersonDevice.AccountId)], t[nameof(PersonDevice.Platform)],
                t[nameof(PersonDevice.Name)], t[nameof(PersonDevice.LastSeenAt)], t[nameof(PersonDevice.CreatedAt)]);
            await db.Database.ExecuteSqlRawAsync($$"""
                INSERT INTO {{t.Name}} ({{t.Columns(nameof(PersonDevice.Id), nameof(PersonDevice.AccountId), nameof(PersonDevice.Token), nameof(PersonDevice.Platform),
                    nameof(PersonDevice.Name), nameof(PersonDevice.CreatedAt), nameof(PersonDevice.LastSeenAt))}})
                VALUES ({0}, {1}, {2}, {3}, {4}, {5}, {6})
                ON CONFLICT ({{t[nameof(PersonDevice.Token)]}}) DO UPDATE SET {{account}} = EXCLUDED.{{account}}, {{platformColumn}} = EXCLUDED.{{platformColumn}},
                    {{nameColumn}} = EXCLUDED.{{nameColumn}}, {{seen}} = EXCLUDED.{{seen}},
                    {{created}} = CASE WHEN {{t.Name}}.{{account}} = EXCLUDED.{{account}} THEN {{t.Name}}.{{created}} ELSE EXCLUDED.{{created}} END
                """, [Guid.NewGuid(), me, token, platform, name, now, now], ct);
            device = await db.Devices.AsNoTracking().FirstAsync(d => d.Token == token, ct);

            List<Guid> beyond = await db.Devices.AsNoTracking().Where(d => d.AccountId == me).OrderByDescending(d => d.LastSeenAt).ThenByDescending(d => d.CreatedAt)
                .Skip(MaxPerPerson).Select(d => d.Id).ToListAsync(ct);
            if (beyond.Count > 0)
            {
                await db.Devices.Where(d => beyond.Contains(d.Id)).ExecuteDeleteAsync(ct);
            }
        }

        // A person's address on the push channel is themselves: the channel finds their phones when it sends.
        await addresses.RememberAsync(me, PushChannel.ChannelKey, me.ToString(), ct);
        if (before is { } previous && previous != me)
        {
            await SettleAsync(previous, ct);
        }

        return new DeviceDto(device.Id, device.Platform, device.Name, device.CreatedAt, device.LastSeenAt);
    }

    /// <summary>Forgets one of the person's phones (removed on the web).</summary>
    public async Task UnregisterAsync(Guid me, Guid id, CancellationToken ct)
    {
        await using (AsyncServiceScope scope = scopes.CreateAsyncScope())
        {
            if (await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().Devices.Where(d => d.AccountId == me && d.Id == id).ExecuteDeleteAsync(ct) == 0)
            {
                throw new EntityNotFoundException(typeof(PersonDevice), id);
            }
        }

        await SettleAsync(me, ct);
    }

    /// <summary>Forgets the person's phone by its token (the app signing out); nothing to do when it's gone already.</summary>
    public async Task UnregisterAsync(Guid me, string? token, CancellationToken ct)
    {
        token = (token ?? "").Trim();
        if (token.Length == 0)
        {
            throw new UserFriendlyException("Name the phone to forget by its push token.");
        }

        await using (AsyncServiceScope scope = scopes.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().Devices.Where(d => d.AccountId == me && d.Token == token).ExecuteDeleteAsync(ct);
        }

        await SettleAsync(me, ct);
    }

    /// <summary>Forgets all the person's phones (they removed the push channel).</summary>
    public async Task UnregisterAllAsync(Guid me, CancellationToken ct)
    {
        await using (AsyncServiceScope scope = scopes.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().Devices.Where(d => d.AccountId == me).ExecuteDeleteAsync(ct);
        }

        await SettleAsync(me, ct);
    }

    public async Task<bool> AnyAsync(Guid accountId, CancellationToken ct)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().Devices.AnyAsync(d => d.AccountId == accountId, ct);
    }

    /// <summary>The push tokens of the person's phones, the one seen last first.</summary>
    public async Task<List<string>> TokensAsync(Guid accountId, CancellationToken ct)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<INotifyDbContext>().Devices.AsNoTracking().Where(d => d.AccountId == accountId)
            .OrderByDescending(d => d.LastSeenAt).Select(d => d.Token).ToListAsync(ct);
    }

    /// <summary>Forgets a token Firebase says is gone (the app was removed, or its token replaced), whoever's it was.</summary>
    public async Task DropAsync(string token, CancellationToken ct)
    {
        Guid? owner;
        await using (AsyncServiceScope scope = scopes.CreateAsyncScope())
        {
            INotifyDbContext db = scope.ServiceProvider.GetRequiredService<INotifyDbContext>();
            owner = await db.Devices.AsNoTracking().Where(d => d.Token == token).Select(d => (Guid?)d.AccountId).FirstOrDefaultAsync(ct);
            await db.Devices.Where(d => d.Token == token).ExecuteDeleteAsync(ct);
        }

        if (owner is { } account)
        {
            await SettleAsync(account, ct);
        }
    }

    /// <summary>
    /// With no phone left, the person has no address on the push channel; if it was how they chose to hear, they hear by
    /// mail again, rather than by a channel that can't reach them.
    /// </summary>
    private async Task SettleAsync(Guid accountId, CancellationToken ct)
    {
        await using AsyncServiceScope scope = scopes.CreateAsyncScope();
        INotifyDbContext db = scope.ServiceProvider.GetRequiredService<INotifyDbContext>();
        if (await db.Devices.AnyAsync(d => d.AccountId == accountId, ct))
        {
            return;
        }

        string mail = options.Value.MailChannel;
        await db.ChannelAddresses.Where(a => a.AccountId == accountId && a.Channel == PushChannel.ChannelKey).ExecuteDeleteAsync(ct);
        await db.NotificationSettings.Where(s => s.AccountId == accountId && s.Channel == PushChannel.ChannelKey)
            .ExecuteUpdateAsync(u => u.SetProperty(s => s.Channel, mail).SetProperty(s => s.UpdatedAt, DateTime.UtcNow), ct);
    }
}
