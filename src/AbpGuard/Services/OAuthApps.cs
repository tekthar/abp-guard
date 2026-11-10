using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Text.Json;
using AbpGuard.Controllers;
using AbpGuard.Acting;
using OpenIddict.Abstractions;
using Volo.Abp;
using Volo.Abp.DependencyInjection;
using Volo.Abp.Domain.Entities;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.Extensions.Options;

namespace AbpGuard.Services;

/// <summary>An app that may ask people to act for them: an MCP client that registered itself, or one a site admin made.</summary>
public sealed record OAuthAppDto(string ClientId, string Name, string Kind, bool Confidential, List<string> RedirectUris, int People);

/// <summary>An app just made by an admin: the only time a confidential app's secret is shown.</summary>
public sealed record NewOAuthAppDto(OAuthAppDto App, string? Secret);

/// <summary>An app to make: its name, where it may send people back to, and whether it keeps a secret (a server-side app).</summary>
public sealed record CreateOAuthAppInput(string Name, List<string> RedirectUris, [property: JsonRequired] bool Confidential);

/// <summary>What a consent page shows about an app: its name, whether it registered itself, and where it sends people back.</summary>
public sealed record OAuthClientDto(string ClientId, string Name, string Kind, List<string> RedirectHosts);

/// <summary>An app a person has allowed to act for them: which, with what access, since when.</summary>
public sealed record OAuthGrantDto(string Id, string ClientId, string AppName, string Access, DateTimeOffset? GrantedAt);

/// <summary>A dynamic client registration (RFC 7591) as MCP clients send it; only what Guard uses.</summary>
public sealed record ClientRegistrationInput(
    [property: System.Text.Json.Serialization.JsonPropertyName("client_name")] string? ClientName,
    [property: System.Text.Json.Serialization.JsonPropertyName("redirect_uris")] List<string>? RedirectUris,
    [property: System.Text.Json.Serialization.JsonPropertyName("grant_types")] List<string>? GrantTypes,
    [property: System.Text.Json.Serialization.JsonPropertyName("response_types")] List<string>? ResponseTypes,
    [property: System.Text.Json.Serialization.JsonPropertyName("token_endpoint_auth_method")] string? TokenEndpointAuthMethod);

/// <summary>The scopes and properties of OAuth for agents.</summary>
public static class OAuthAgents
{
    /// <summary>How an app came (kept in GuardNames.AppKindProperty): it registered itself (an MCP client), or a site admin made it.</summary>
    public const string Registered = "registered";
    public const string Made = "admin";

    /// <summary>
    /// What an app a person allows is granted: the host's API (GuardOptions.ApiScope), and refreshing (a refresh token)
    /// only when the app asked for it.
    /// </summary>
    public static ImmutableArray<string> GrantedScopes(string apiScope, bool offline) => offline ? [apiScope, Scopes.OfflineAccess] : [apiScope];
}

/// <summary>
/// OAuth for agents: apps that ask a person to let them act for them, through the authorization code flow
/// with PKCE and a consent page. MCP clients register themselves (RFC 7591), as public clients; site admins make apps
/// for other systems, public or confidential. A person sees and revokes the apps they've allowed.
/// </summary>
public sealed class OAuthApps(IOpenIddictApplicationManager applications, IOpenIddictAuthorizationManager authorizations, IOpenIddictTokenManager tokens,
    ISecurityAudit audit, IGuardRateLimits limits, IOptions<GuardOptions> options, IOptions<GuardNames> names) : ITransientDependency
{
    private const int RegistrationsPerHour = 20;

    /// <summary>
    /// Registers an MCP client (RFC 7591): a public client (no secret) that must use PKCE, sending people back only to a
    /// loopback address, an https address or an app's own scheme. At most 20 an hour from one address.
    /// </summary>
    public async Task<OAuthAppDto> RegisterAsync(ClientRegistrationInput input, string? ip, CancellationToken cancellationToken)
    {
        // Counted for the whole site, so several servers allow no more than one.
        if (!await limits.TryTakeAsync($"mcp-register|{ip ?? "unknown"}", RegistrationsPerHour, TimeSpan.FromHours(1), cancellationToken))
        {
            throw new BusinessException("too_many_registrations", "Too many registrations from here; try again in an hour.");
        }

        if (input.TokenEndpointAuthMethod is not (null or "none"))
        {
            throw Invalid("Apps that register themselves are public clients: token_endpoint_auth_method is none.");
        }

        if (input.GrantTypes?.Except([GrantTypes.AuthorizationCode, GrantTypes.RefreshToken]).Any() == true
            || input.ResponseTypes?.Except([ResponseTypes.Code]).Any() == true)
        {
            throw Invalid("Only the authorization code flow (with refresh tokens) is offered.");
        }

        string name = Name(input.ClientName ?? "An MCP client");
        List<Uri> redirects = RedirectUris(input.RedirectUris);
        object app = await applications.CreateAsync(Descriptor(GenerateClientId(), name, redirects, secret: null, OAuthAgents.Registered), cancellationToken);
        OAuthAppDto dto = await ToDtoAsync(app, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.OAuthAppRegistered, new AuditTarget("OAuthApp", null, dto.ClientId), new { name, redirects = dto.RedirectUris },
            cancellationToken);
        return dto;
    }

    /// <summary>An app a site admin makes for another system; a confidential one gets a secret, shown once.</summary>
    public async Task<NewOAuthAppDto> CreateAsync(CreateOAuthAppInput input, CancellationToken cancellationToken)
    {
        string name = Name(input.Name);
        List<Uri> redirects = RedirectUris(input.RedirectUris);
        string? secret = input.Confidential ? names.Value.AppSecretPrefix + Base64Url(RandomNumberGenerator.GetBytes(32)) : null;
        object app = await applications.CreateAsync(Descriptor(GenerateClientId(), name, redirects, secret, OAuthAgents.Made), cancellationToken);
        OAuthAppDto dto = await ToDtoAsync(app, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.OAuthAppCreated, new AuditTarget("OAuthApp", null, dto.ClientId),
            new { name, redirects = dto.RedirectUris, confidential = input.Confidential }, cancellationToken);
        return new NewOAuthAppDto(dto, secret);
    }

    /// <summary>Every app but the host's own web server, newest last.</summary>
    public async Task<List<OAuthAppDto>> ListAsync(CancellationToken cancellationToken)
    {
        List<OAuthAppDto> apps = [];
        // Read each list whole before asking more of the store: one query at a time on its connection.
        foreach (object app in await All(applications.ListAsync(count: 500, offset: null, cancellationToken)))
        {
            if (await applications.GetClientIdAsync(app, cancellationToken) != options.Value.Clients.Web)
            {
                apps.Add(await ToDtoAsync(app, cancellationToken));
            }
        }

        return apps;
    }

    /// <summary>Removes an app: everyone's permission for it ends, and its tokens stop working.</summary>
    public async Task DeleteAsync(string clientId, CancellationToken cancellationToken)
    {
        object app = await FindAsync(clientId, cancellationToken);
        string? name = await applications.GetDisplayNameAsync(app, cancellationToken);
        // OpenIddict removes the app with its permissions and tokens, in one transaction.
        await applications.DeleteAsync(app, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.OAuthAppDeleted, new AuditTarget("OAuthApp", null, clientId), new { name }, cancellationToken);
    }

    /// <summary>What the consent page says about an app.</summary>
    public async Task<OAuthClientDto> DescribeAsync(string clientId, CancellationToken cancellationToken)
    {
        OAuthAppDto app = await ToDtoAsync(await FindAsync(clientId, cancellationToken), cancellationToken);
        return new OAuthClientDto(app.ClientId, app.Name, app.Kind, [.. app.RedirectUris.Select(u => new Uri(u)).Select(u => u.IsLoopback ? $"{u.Host} (this computer)" : u.Host).Distinct()]);
    }

    /// <summary>
    /// The person's permission for an app, kept until they revoke it: a permanent authorization recording the access they
    /// allowed. Its id is what the app's tokens carry as their token id.
    /// </summary>
    public async Task<string> AllowAsync(Guid accountId, string clientId, string access, ImmutableArray<string> scopes, CancellationToken cancellationToken)
    {
        object app = await FindAsync(clientId, cancellationToken);
        string appId = (await applications.GetIdAsync(app, cancellationToken))!;
        // The person's latest answer stands: the same access and scopes keep the permission they gave before; another
        // replaces it, ending what the app got under the old one.
        foreach (object earlier in await All(authorizations.FindAsync(accountId.ToString(), appId, Statuses.Valid, AuthorizationTypes.Permanent, null, cancellationToken)))
        {
            ImmutableDictionary<string, JsonElement> given = await authorizations.GetPropertiesAsync(earlier, cancellationToken);
            if (given.TryGetValue(names.Value.AppAccessProperty, out JsonElement was) && was.GetString() == access
                && (await authorizations.GetScopesAsync(earlier, cancellationToken)).ToHashSet().SetEquals(scopes))
            {
                return (await authorizations.GetIdAsync(earlier, cancellationToken))!;
            }

            await RevokeAsync(earlier, cancellationToken);
        }

        object authorization = await authorizations.CreateAsync(new OpenIddictAuthorizationDescriptor
        {
            ApplicationId = appId,
            CreationDate = DateTimeOffset.UtcNow,
            Status = Statuses.Valid,
            Subject = accountId.ToString(),
            Type = AuthorizationTypes.Permanent,
            Properties = { [names.Value.AppAccessProperty] = JsonSerializer.SerializeToElement(access) },
        }.WithScopes(scopes), cancellationToken);
        string id = (await authorizations.GetIdAsync(authorization, cancellationToken))!;
        await audit.WriteAsync(SecurityAuditTypes.OAuthConsentGranted, new AuditTarget("Account", accountId, null),
            new { app = await applications.GetDisplayNameAsync(app, cancellationToken), clientId, access }, cancellationToken);
        return id;
    }

    /// <summary>The apps the person has allowed, still in force.</summary>
    public async Task<List<OAuthGrantDto>> GrantsAsync(Guid accountId, CancellationToken cancellationToken)
    {
        List<OAuthGrantDto> grants = [];
        Dictionary<string, (string ClientId, string Name)> apps = [];
        foreach (object authorization in await All(authorizations.FindBySubjectAsync(accountId.ToString(), cancellationToken)))
        {
            if (await authorizations.GetStatusAsync(authorization, cancellationToken) != Statuses.Valid
                || await authorizations.GetTypeAsync(authorization, cancellationToken) != AuthorizationTypes.Permanent
                || await authorizations.GetApplicationIdAsync(authorization, cancellationToken) is not { } appId)
            {
                continue;
            }

            if (!apps.TryGetValue(appId, out (string ClientId, string Name) app))
            {
                object? found = await applications.FindByIdAsync(appId, cancellationToken);
                app = found is null ? ("", "(removed)") : ((await applications.GetClientIdAsync(found, cancellationToken))!, (await applications.GetDisplayNameAsync(found, cancellationToken)) ?? "");
                apps[appId] = app;
            }

            ImmutableDictionary<string, JsonElement> properties = await authorizations.GetPropertiesAsync(authorization, cancellationToken);
            grants.Add(new OAuthGrantDto((await authorizations.GetIdAsync(authorization, cancellationToken))!, app.ClientId, app.Name,
                properties.TryGetValue(names.Value.AppAccessProperty, out JsonElement access) ? access.GetString() ?? "read" : "read",
                await authorizations.GetCreationDateAsync(authorization, cancellationToken)));
        }

        return [.. grants.OrderByDescending(g => g.GrantedAt)];
    }

    /// <summary>Ends a permission the person gave: the app can't refresh its tokens from now on.</summary>
    public async Task RevokeGrantAsync(Guid accountId, string id, CancellationToken cancellationToken)
    {
        object authorization = await authorizations.FindByIdAsync(id, cancellationToken) is { } found && await authorizations.GetSubjectAsync(found, cancellationToken) == accountId.ToString()
            ? found
            : throw new EntityNotFoundException("There's no such app you've allowed.");
        await RevokeAsync(authorization, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.OAuthConsentRevoked, new AuditTarget("Account", accountId, null), new { authorization = id }, cancellationToken);
    }

    /// <summary>Whether a permission is still in force: a refresh checks it, so a revoked one ends the app's access.</summary>
    public async Task<bool> IsValidAsync(string? authorizationId, CancellationToken cancellationToken) =>
        authorizationId is not null && await authorizations.FindByIdAsync(authorizationId, cancellationToken) is { } found
        && await authorizations.GetStatusAsync(found, cancellationToken) == Statuses.Valid;

    private async Task RevokeAsync(object authorization, CancellationToken cancellationToken)
    {
        string id = (await authorizations.GetIdAsync(authorization, cancellationToken))!;
        await authorizations.TryRevokeAsync(authorization, cancellationToken);
        await tokens.RevokeByAuthorizationIdAsync(id, cancellationToken);
    }

    private static async Task<List<object>> All(IAsyncEnumerable<object> items)
    {
        List<object> list = [];
        await foreach (object item in items)
        {
            list.Add(item);
        }

        return list;
    }

    private async Task<object> FindAsync(string clientId, CancellationToken cancellationToken) =>
        clientId != options.Value.Clients.Web && await applications.FindByClientIdAsync(clientId, cancellationToken) is { } app
            ? app
            : throw new EntityNotFoundException("There's no such app.");

    private async Task<OAuthAppDto> ToDtoAsync(object app, CancellationToken cancellationToken)
    {
        ImmutableDictionary<string, JsonElement> properties = await applications.GetPropertiesAsync(app, cancellationToken);
        string appId = (await applications.GetIdAsync(app, cancellationToken))!;
        int people = 0;
        foreach (object authorization in await All(authorizations.FindByApplicationIdAsync(appId, cancellationToken)))
        {
            if (await authorizations.GetStatusAsync(authorization, cancellationToken) == Statuses.Valid
                && await authorizations.GetTypeAsync(authorization, cancellationToken) == AuthorizationTypes.Permanent)
            {
                people++;
            }
        }

        return new OAuthAppDto((await applications.GetClientIdAsync(app, cancellationToken))!, (await applications.GetDisplayNameAsync(app, cancellationToken)) ?? "",
            properties.TryGetValue(names.Value.AppKindProperty, out JsonElement kind) ? kind.GetString() ?? OAuthAgents.Made : OAuthAgents.Made,
            await applications.GetClientTypeAsync(app, cancellationToken) == ClientTypes.Confidential,
            [.. (await applications.GetRedirectUrisAsync(app, cancellationToken)).Order(StringComparer.Ordinal)], people);
    }

    private OpenIddictApplicationDescriptor Descriptor(string clientId, string name, List<Uri> redirects, string? secret, string kind)
    {
        OpenIddictApplicationDescriptor descriptor = new()
        {
            ClientId = clientId,
            ClientSecret = secret,
            ClientType = secret is null ? ClientTypes.Public : ClientTypes.Confidential,
            ConsentType = ConsentTypes.Explicit,
            DisplayName = name,
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.Endpoints.Revocation,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                Permissions.Prefixes.Scope + options.Value.ApiScope,
                Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                Permissions.Prefixes.Scope + names.Value.ReadScope,
            },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange },
            Properties = { [names.Value.AppKindProperty] = JsonSerializer.SerializeToElement(kind) },
        };
        foreach (Uri redirect in redirects)
        {
            descriptor.RedirectUris.Add(redirect);
        }

        return descriptor;
    }

    /// <summary>
    /// Where an app may send people back: https, http only to this computer (a loopback address, as native apps and
    /// local agents use), or an app's own scheme (RFC 8252); never a scheme a browser runs or reads.
    /// </summary>
    public static List<Uri> RedirectUris(IEnumerable<string>? given)
    {
        List<string> uris = given?.Where(u => !string.IsNullOrWhiteSpace(u)).Select(u => u.Trim()).Distinct(StringComparer.Ordinal).ToList() ?? [];
        if (uris.Count is < 1 or > 10)
        {
            throw Invalid("An app sends people back to 1 to 10 addresses (redirect_uris).");
        }

        List<Uri> result = [];
        foreach (string text in uris)
        {
            if (!Uri.TryCreate(text, UriKind.Absolute, out Uri? uri) || !string.IsNullOrEmpty(uri.Fragment))
            {
                throw Invalid($"{text} isn't an address an app can be sent back to.");
            }

            bool allowed = uri.Scheme switch
            {
                "https" => true,
                "http" => uri.IsLoopback,
                "javascript" or "data" or "file" or "vbscript" or "about" or "blob" or "ftp" or "ws" or "wss" => false,
                _ => true, // an app's own scheme (cursor://, vscode://, com.example.app:/)
            };
            if (!allowed)
            {
                throw Invalid($"{text}: an app is sent back to https, to this computer over http, or to its own scheme.");
            }

            result.Add(uri);
        }

        return result;
    }

    private static string Name(string name) =>
        name.Trim() is { Length: >= 1 and <= 100 } trimmed ? trimmed : throw Invalid("An app's name is 1 to 100 characters.");

    private static BusinessException Invalid(string message) => new("invalid_client_metadata", message);

    private string GenerateClientId() => names.Value.AppIdPrefix + Base64Url(RandomNumberGenerator.GetBytes(16));

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

internal static class AuthorizationDescriptors
{
    public static OpenIddictAuthorizationDescriptor WithScopes(this OpenIddictAuthorizationDescriptor descriptor, IEnumerable<string> scopes)
    {
        foreach (string scope in scopes)
        {
            descriptor.Scopes.Add(scope);
        }

        return descriptor;
    }
}
