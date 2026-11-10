using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using AbpGuard.Domain;
using AbpGuard.Services;
using AbpGuard.Acting;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Volo.Abp;
using Volo.Abp.Uow;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.Extensions.Options;

namespace AbpGuard.Controllers;

/// <summary>
/// The authorization endpoint for apps and agents: the authorization code flow with PKCE. The web app
/// forwards a person's browser here with their session; someone not signed in is sent to sign in, then to the consent
/// page (<c>/oauth/consent</c>), whose answer comes back here as a POST. Allowing records a permanent permission, with
/// the access the person chose (reading only, or reading and writing, never more than they may do), and the app gets a
/// code. Tokens can't allow apps: it takes the person at the browser.
/// </summary>
[ApiExplorerSettings(IgnoreApi = true)]
[UnitOfWork(IsDisabled = true)]
[GuardFeature(nameof(GuardFeatures.OAuthApps))]
public class AuthorizationController(OAuthApps apps, GuardDb guardDb, IOptions<GuardOptions> options) : GuardControllerBase
{
    public const string DecisionParameter = "decision";
    public const string AccessParameter = "access";

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [AllowAnonymous]
    // Reviewed (S4502): a decision is taken only from a POST, and the session that makes it someone's comes from its
    // SameSite=Lax cookie, which browsers don't send with another site's POST, and with the session's
    // anti-forgery value in the form; without both it arrives signed out.
#pragma warning disable S4502
    [IgnoreAntiforgeryToken]
#pragma warning restore S4502
    public async Task<IActionResult> Authorize(CancellationToken cancellationToken)
    {
        OpenIddictRequest request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenIddict server request cannot be retrieved.");
        string query = QueryString.Create(request.GetParameters()
            .Where(p => p.Key != DecisionParameter && p.Key != AccessParameter && p.Key != WebSessionHandler.Names(HttpContext).Csrf)
            .Select(p => new KeyValuePair<string, string?>(p.Key, p.Value.ToString()))).ToUriComponent();

        if (Acting.SubjectId is not { } accountId)
        {
            return request.HasPromptValue(PromptValues.None)
                ? Refuse(Errors.LoginRequired, $"Sign in to {options.Value.Texts.Product()} first.")
                : LocalRedirect("/login?next=" + Uri.EscapeDataString("/connect/authorize" + query));
        }

        // The browser's session only: any bearer token (the phone's or a script's from the token endpoint too) skips the
        // session's anti-forgery check and the consent page.
        if (Acting.TokenId is not null || User.Identity?.AuthenticationType != WebSessionHandler.SchemeName)
        {
            return Refuse(Errors.AccessDenied, "An app is allowed by the person at the browser, not with a token.");
        }

        Account? account = await guardDb.RunAsync(db => db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken),
            cancellationToken: cancellationToken);
        if (account is null || account.Status != AccountStatus.Active)
        {
            return Refuse(Errors.AccessDenied, "This account can't allow apps.");
        }

        string? decision = request.GetParameter(DecisionParameter)?.ToString();
        if (!HttpMethods.IsPost(Request.Method) || decision is null)
        {
            return request.HasPromptValue(PromptValues.None)
                ? Refuse(Errors.ConsentRequired, "The person hasn't allowed this app yet.")
                // The consent page is a path of this site (GuardPageOptions); the request only adds its encoded query.
                : LocalRedirect(options.Value.Pages.Consent + query);
        }

        if (decision != "allow")
        {
            return Refuse(Errors.AccessDenied, "The person didn't allow it.");
        }

        // Reading only unless the person chose to let it change things too, and never more than the app asked for.
        string access = request.GetParameter(AccessParameter)?.ToString() == TokenAccess.Write && !request.HasScope(WebSessionHandler.Wire(HttpContext).ReadScope)
            ? TokenAccess.Write
            : TokenAccess.Read;
        ImmutableArray<string> scopes = OAuthAgents.GrantedScopes(options.Value.ApiScope, request.HasScope(Scopes.OfflineAccess));
        string authorizationId = await apps.AllowAsync(accountId, request.ClientId!, access, scopes, cancellationToken);
        return SignIn(AppPrincipals.For(account, authorizationId, access, scopes, WebSessionHandler.Wire(HttpContext)), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private ForbidResult Refuse(string error, string description) =>
        Forbid(new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
        }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
}

/// <summary>The claims an app's tokens carry: the person, the permission (as the token's id, so it can't step up), and its access.</summary>
public static class AppPrincipals
{
    public static ClaimsPrincipal For(Account account, string authorizationId, string access, IEnumerable<string> scopes, GuardNames names)
    {
        ClaimsIdentity identity = new(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, account.Id.ToString())
            .SetClaim(Claims.Name, account.Username)
            .SetClaim("display_name", account.DisplayName)
            .SetClaim(names.TokenClaim, authorizationId)
            .SetClaim(names.TokenAccessClaim, access);
        identity.SetScopes(scopes);
        identity.SetAuthorizationId(authorizationId);
        identity.SetDestinations(_ => [Destinations.AccessToken]);
        return new ClaimsPrincipal(identity);
    }
}

/// <summary>
/// Dynamic client registration (RFC 7591, M7): MCP clients register themselves before they ask a person to allow them.
/// Each is a public client that must use PKCE; site admins see and remove them. A site turns it off with
/// <c>Guard:Oidc:ClientRegistration</c> false.
/// </summary>
[ApiExplorerSettings(IgnoreApi = true)]
[GuardFeature(nameof(GuardFeatures.ClientRegistration))]
public class ClientRegistrationController(OAuthApps apps, IConfiguration configuration) : GuardControllerBase
{
    [HttpPost("~/connect/register")]
    [AllowAnonymous]
#pragma warning disable S4502 // reviewed: registration is anonymous, by machines (RFC 7591); no cookie acts for anyone here
    [IgnoreAntiforgeryToken]
#pragma warning restore S4502
    public async Task<IActionResult> Register([FromBody] ClientRegistrationInput input, CancellationToken cancellationToken)
    {
        if (!configuration.GetValue("Guard:Oidc:ClientRegistration", true))
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "access_denied", error_description = "Apps can't register themselves on this site: ask a site admin." });
        }

        try
        {
            OAuthAppDto app = await apps.RegisterAsync(input, HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken);
            return StatusCode(StatusCodes.Status201Created, new Dictionary<string, object?>
            {
                ["client_id"] = app.ClientId,
                ["client_id_issued_at"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["client_name"] = app.Name,
                ["redirect_uris"] = app.RedirectUris,
                ["grant_types"] = new[] { GrantTypes.AuthorizationCode, GrantTypes.RefreshToken },
                ["response_types"] = new[] { ResponseTypes.Code },
                ["token_endpoint_auth_method"] = "none",
            });
        }
        catch (BusinessException ex) when (ex.Code is "invalid_client_metadata" or "too_many_registrations")
        {
            return StatusCode(ex.Code == "too_many_registrations" ? StatusCodes.Status429TooManyRequests : StatusCodes.Status400BadRequest,
                new { error = ex.Code == "too_many_registrations" ? "temporarily_unavailable" : ex.Code, error_description = ex.Message });
        }
    }
}

/// <summary>
/// Apps and agents: site admins list every app, make one for another system (a confidential one's secret shown
/// once, after a step-up) and remove one; anyone signed in reads what a consent page says about an app; a person sees
/// the apps they've allowed and takes a permission back.
/// </summary>
[Route("api/guard")]
[Authorize]
[GuardFeature(nameof(GuardFeatures.OAuthApps))]
public class OAuthAppsController(OAuthApps apps) : GuardControllerBase
{
    [HttpGet("oauth/apps")]
    [Authorize(Policy = GuardPolicies.Admin)]
    public Task<List<OAuthAppDto>> List(CancellationToken cancellationToken) => apps.ListAsync(cancellationToken);

    [HttpPost("oauth/apps")]
    [Authorize(Policy = GuardPolicies.Admin)]
    [StepUp]
    public Task<NewOAuthAppDto> Create([FromBody] CreateOAuthAppInput input, CancellationToken cancellationToken) => apps.CreateAsync(input, cancellationToken);

    [HttpDelete("oauth/apps/{clientId}")]
    [Authorize(Policy = GuardPolicies.Admin)]
    public async Task<NoContentResult> Delete(string clientId, CancellationToken cancellationToken)
    {
        await apps.DeleteAsync(clientId, cancellationToken);
        return NoContent();
    }

    [HttpGet("oauth/clients/{clientId}")]
    public Task<OAuthClientDto> Client(string clientId, CancellationToken cancellationToken) => apps.DescribeAsync(clientId, cancellationToken);

    [HttpGet("me/apps")]
    public Task<List<OAuthGrantDto>> Mine(CancellationToken cancellationToken) => apps.GrantsAsync(CurrentAccountId, cancellationToken);

    [HttpDelete("me/apps/{id}")]
    public async Task<NoContentResult> Revoke(string id, CancellationToken cancellationToken)
    {
        await apps.RevokeGrantAsync(CurrentAccountId, id, cancellationToken);
        return NoContent();
    }
}
