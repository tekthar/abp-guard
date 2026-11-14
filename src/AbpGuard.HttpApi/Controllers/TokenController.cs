using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AbpGuard.Domain;
using AbpGuard.Services;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Volo.Abp.AspNetCore.Mvc;
using Volo.Abp.Uow;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.Extensions.Options;

namespace AbpGuard.Controllers;

/// <summary>
/// The OpenIddict token endpoint. In M0 it serves the first-party Next.js server only: the password
/// grant (checked against guard's directories, with rate limiting and audit) and refresh tokens
/// (re-checking that the account is still active). See.
/// Tokens say when the person last proved who they are (<c>auth_time</c>, <c>amr</c>), and a refresh keeps it. A
/// refresh that carries <c>step_up_password</c> is a step-up: the account's own directory checks the password
/// and the new tokens start a new window; only the host's own web server may ask, and too many failures end the session.
/// A person whose groups ask for a second factor, or who set one up, gets no tokens from the password alone:
/// the answer is <c>second_factor_required</c> with a <c>ticket</c>, its <c>methods</c>, and <c>enrol</c> when they must
/// set one up first; the ticket and a code then go through the second step's grant (GuardNames.SecondFactorGrantType).
/// </summary>
[ApiExplorerSettings(IgnoreApi = true)]
[UnitOfWork(IsDisabled = true)]
public class TokenController(AuthService auth, GuardDb guardDb, IOpenIddictTokenManager tokens, OAuthApps apps, Services.TwoFactor.SecondFactors secondFactors,
    IOptions<GuardOptions> options)
    : AbpControllerBase
{
    /// <summary>The grant type of the second step, with <c>ticket</c>, <c>method</c> and <c>code</c>: GuardNames.SecondFactorGrantType.</summary>
    private GuardNames Names => Services.WebSessionHandler.Wire(HttpContext);

    // A code or refresh token made before the site renamed its claims and scopes reads as made under today's names, so the
    // tokens made from it carry today's; one with such a claim under a name Guard doesn't know is refused (GuardNames.Former).
    private async Task<ClaimsPrincipal?> GrantedAsync()
    {
        AuthenticateResult result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        return result.Principal is { } principal ? Names.Current(principal, Claims.Private.Scope) : null;
    }

    [HttpPost("~/connect/token")]
    [AllowAnonymous]
#pragma warning disable S4502 // reviewed: the token endpoint takes a client's grant (a code, a refresh token), never a cookie
    [IgnoreAntiforgeryToken]
#pragma warning restore S4502
    [Produces("application/json")]
    public async Task<IActionResult> Exchange(CancellationToken cancellationToken)
    {
        OpenIddictRequest request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenIddict server request cannot be retrieved.");

        if (request.IsPasswordGrantType())
        {
            string? ip = HttpContext.Connection.RemoteIpAddress?.ToString();
            LoginResult result = await auth.LoginAsync(request.Username ?? string.Empty, request.Password ?? string.Empty, ip, cancellationToken);
            if (!result.Succeeded)
            {
                return Refuse(result.ErrorCode switch
                {
                    "too_many_attempts" => "Too many failed attempts. Try again in 15 minutes.",
                    "account_merged" => $"This account was merged into {result.MergedInto}. Sign in as {result.MergedInto}.",
                    _ => "The username or password is incorrect.",
                });
            }

            if (await secondFactors.ChallengeAsync(result.Account!.Id, request.ClientId ?? "", string.Join(' ', request.GetScopes()), ip, cancellationToken) is { } challenge)
            {
                return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = SecondFactorRequiredError,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = challenge.Enrol
                        ? "Set up a second factor to sign in."
                        : "Enter the code of your second factor.",
                }, new Dictionary<string, object?>
                {
                    ["ticket"] = challenge.Ticket,
                    ["methods"] = challenge.Methods.ToArray(),
                    ["enrol"] = challenge.Enrol,
                    ["strong"] = challenge.Strong,
                }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            return SignIn(CreatePrincipal(result.Account!, request.GetScopes(), DateTimeOffset.UtcNow), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // The second step: the ticket from the password grant, for the same client, with a code.
        if (request.GrantType == Names.SecondFactorGrantType)
        {
            Services.TwoFactor.SecondStepResult step = await secondFactors.PassAsync(request.GetParameter("ticket")?.ToString() ?? "",
                request.GetParameter("method")?.ToString(), request.GetParameter("code")?.ToString(), request.ClientId ?? "",
                HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken);
            if (step.Passed is not { } passed)
            {
                return Refuse(step.Error switch
                {
                    "too_many_attempts" => "Too many wrong codes. Try again in 15 minutes.",
                    "second_factor_failed" => "The code is incorrect.",
                    _ => "This sign-in has expired. Sign in again.",
                }, step.Error == "second_factor_failed" ? SecondFactorFailedError : Errors.InvalidGrant);
            }

            Account? account = await guardDb.RunAsync(db => db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == passed.AccountId, cancellationToken),
                cancellationToken: cancellationToken);
            if (account is null || account.Status != AccountStatus.Active)
            {
                return Refuse("The account is no longer active.");
            }

            return SignIn(CreatePrincipal(account, (passed.Scopes ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries), DateTimeOffset.UtcNow, secondFactor: true),
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // An app's code: exchanged once, with its PKCE verifier (OpenIddict checks both), while the person's
        // permission stands and their account is active.
        if (request.IsAuthorizationCodeGrantType())
        {
            return await AppTokensAsync(await GrantedAsync(), cancellationToken);
        }

        if (request.IsRefreshTokenGrantType())
        {
            ClaimsPrincipal? refreshed = await GrantedAsync();
            if (refreshed?.GetClaim(Names.TokenClaim) is not null)
            {
                if (request.GetParameter(StepUpParameter) is not null)
                {
                    return Refuse($"Only {options.Value.Texts.Product()}'s own web app can ask for a step-up.", Errors.UnauthorizedClient);
                }

                return await AppTokensAsync(refreshed, cancellationToken);
            }

            if (!Guid.TryParse(refreshed?.GetClaim(Claims.Subject), out Guid accountId))
            {
                return Refuse("The session is no longer valid.");
            }

            // Re-check on every refresh, so a deactivated or locked account loses access within one access-token lifetime.
            Account? account = await guardDb.RunAsync(db => db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken),
                cancellationToken: cancellationToken);
            if (account is null || account.Status != AccountStatus.Active)
            {
                return Refuse("The account is no longer active.");
            }

            // When the person last proved who they are travels with the session; a step-up moves it on.
            DateTimeOffset? authTime = long.TryParse(refreshed!.GetClaim(Claims.AuthenticationTime), out long seconds)
                ? DateTimeOffset.FromUnixTimeSeconds(seconds)
                : null;
            if (request.GetParameter(StepUpParameter)?.ToString() is { } password)
            {
                if (request.ClientId != options.Value.Clients.Web)
                {
                    return Refuse($"Only {options.Value.Texts.Product()}'s own web app can ask for a step-up.", Errors.UnauthorizedClient);
                }

                StepUpResult stepUp = await auth.StepUpAsync(account.Id, password, HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken);
                if (!stepUp.Succeeded)
                {
                    if (stepUp.EndSession && refreshed.GetTokenId() is { } tokenId && await tokens.FindByIdAsync(tokenId, cancellationToken) is { } token)
                    {
                        await tokens.TryRevokeAsync(token, cancellationToken);
                    }

                    return Refuse(stepUp.EndSession ? "Too many wrong passwords: the session has ended. Sign in again."
                        : stepUp.Blocked ? "Too many failed attempts. Try again in 15 minutes." : "The password is incorrect.",
                        stepUp.EndSession ? SessionEndedError : StepUpFailedError);
                }

                // A person with a second factor proves it again too: step_up_method and step_up_code.
                if (await secondFactors.StepUpErrorAsync(account.Id, request.GetParameter(StepUpMethodParameter)?.ToString(),
                        request.GetParameter(StepUpCodeParameter)?.ToString(), HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken) is { } error)
                {
                    return Refuse(error switch
                    {
                        SecondFactorRequiredError => "Enter the code of your second factor too.",
                        "too_many_attempts" => "Too many wrong codes. Try again in 15 minutes.",
                        _ => "The code is incorrect.",
                    }, error == SecondFactorRequiredError ? SecondFactorRequiredError : SecondFactorFailedError);
                }

                authTime = DateTimeOffset.UtcNow;
            }

            // A session that had its second step keeps saying so.
            bool secondFactor = refreshed.GetClaims(Claims.AuthenticationMethodReference).Contains("mfa");
            return SignIn(CreatePrincipal(account, refreshed.GetScopes(), authTime, secondFactor), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return Refuse("This grant type is not supported.", Errors.UnsupportedGrantType);
    }

    /// <summary>
    /// New tokens for an app: the person's permission must still stand and their account be active; the tokens keep
    /// the permission's id and the access the person allowed.
    /// </summary>
    private async Task<IActionResult> AppTokensAsync(ClaimsPrincipal? granted, CancellationToken cancellationToken)
    {
        if (!options.Value.Features.OAuthApps)
        {
            return Refuse("Apps are switched off on this site.");
        }

        if (!Guid.TryParse(granted?.GetClaim(Claims.Subject), out Guid accountId) || !await apps.IsValidAsync(granted!.GetAuthorizationId(), cancellationToken))
        {
            return Refuse("The app is no longer allowed: ask the person again.");
        }

        Account? account = await guardDb.RunAsync(db => db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken),
            cancellationToken: cancellationToken);
        if (account is null || account.Status != AccountStatus.Active)
        {
            return Refuse("The account is no longer active.");
        }

        return SignIn(AppPrincipals.For(account, granted.GetAuthorizationId()!, granted.GetClaim(Names.TokenAccessClaim) ?? TokenAccess.Read,
            granted.GetScopes(), Names), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>The token parameter that makes a refresh a step-up, with the password.</summary>
    public const string StepUpParameter = "step_up_password";

    /// <summary>With a step-up, the method of the person's second factor (<c>app</c>, <c>recovery</c>) and its code.</summary>
    public const string StepUpMethodParameter = "step_up_method";

    public const string StepUpCodeParameter = "step_up_code";

    /// <summary>The step-up's password was wrong; the session goes on.</summary>
    public const string StepUpFailedError = "step_up_failed";

    /// <summary>Too many wrong step-up passwords: the refresh token is revoked.</summary>
    public const string SessionEndedError = "session_ended";

    /// <summary>The password was right, and a second step is needed: the answer carries its ticket.</summary>
    public const string SecondFactorRequiredError = "second_factor_required";

    /// <summary>The second step's code was wrong; the ticket has tries left.</summary>
    public const string SecondFactorFailedError = "second_factor_failed";

    private ClaimsPrincipal CreatePrincipal(Account account, IEnumerable<string> scopes, DateTimeOffset? authTime, bool secondFactor = false)
    {
        ClaimsIdentity identity = new(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            Claims.Name,
            Claims.Role);

        identity.SetClaim(Claims.Subject, account.Id.ToString())
            .SetClaim(Claims.Name, account.Username)
            .SetClaim("display_name", account.DisplayName);
        if (authTime is { } proved)
        {
            // A password checked by the account's directory (OpenID Connect's "pwd"), and a one-time code when there was a
            // second step ("otp", "mfa";).
            identity.SetClaim(Claims.AuthenticationTime, proved.ToUnixTimeSeconds())
                .SetClaims(Claims.AuthenticationMethodReference, secondFactor ? ["pwd", "otp", "mfa"] : ["pwd"]);
        }

        identity.SetScopes(scopes.Intersect([Scopes.OfflineAccess, options.Value.ApiScope]));
        identity.SetDestinations(_ => [Destinations.AccessToken]);
        return new ClaimsPrincipal(identity);
    }

    private ForbidResult Refuse(string description, string error = Errors.InvalidGrant) =>
        Forbid(
            new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
            }),
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
}
