using Microsoft.EntityFrameworkCore;
using AbpGuard.Controllers;
using AbpGuard.Acting;
using OpenIddict.Abstractions;
using Volo.Abp.DependencyInjection;
using Volo.Abp.Domain.Entities;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.Extensions.Options;

namespace AbpGuard.Services;

/// <summary>
/// Where a person is signed in. Kind: browser (a web session), phone (the app's sign-in) or script
/// (a script or tool that signed in with the password, as web). Current: the session or sign-in the request came
/// with. A browser's user agent and address are where it signed in from.
/// </summary>
public sealed record AccountSessionDto(string Id, string Kind, bool Current, DateTime CreatedAt, DateTime? LastSeenAt, DateTime? ExpiresAt, string? UserAgent, string? Ip);

/// <summary>What signing out everywhere ended: browsers' sessions, and the phone app's and scripts' sign-ins.</summary>
public sealed record SessionsEndedDto(int Browsers, int Apps);

public static class SessionKinds
{
    public const string Browser = "browser";
    public const string Phone = "phone";
    public const string Script = "script";
}

/// <summary>
/// A person's sessions, listed and ended: the browsers' (<see cref="WebSessions"/>), and the sign-ins of the
/// phone app and of scripts, which keep a refresh token from the token endpoint under a permission of their own
/// (OpenIddict's ad-hoc authorizations of <c>mobile</c> and <c>web</c>). Ending one of those revokes the
/// permission and its tokens: the refresh token stops at once, the access token within its 15 minutes. Apps the person
/// allowed (OAuth) and personal access tokens have their own lists, and signing out everywhere leaves them.
/// </summary>
public class AccountSessions(GuardDb guardDb, WebSessions web, IOpenIddictApplicationManager applications, IOpenIddictAuthorizationManager authorizations,
    IOpenIddictTokenManager tokens, SecurityLog audit, IOptions<GuardOptions> options) : ITransientDependency
{
    private const int Most = 200;

    private sealed record AppSignIn(string AuthorizationId, string Kind, DateTime CreatedAt, DateTime LastSeenAt, DateTime? ExpiresAt);

    /// <summary>The person's live sessions, the current one first, then the most recently used.</summary>
    public async Task<List<AccountSessionDto>> ListAsync(Guid accountId, Guid? currentSession, string? currentAuthorization, CancellationToken cancellationToken = default)
    {
        currentAuthorization ??= await OpenedByAsync(currentSession, cancellationToken);
        DateTime now = DateTime.UtcNow;
        // The phone app's web views belong to its sign-in, listed once.
        List<AccountSessionDto> sessions = await guardDb.RunAsync(db => db.WebSessions.AsNoTracking()
            .Where(s => s.AccountId == accountId && s.RevokedAt == null && s.ExpiresAt > now && s.ParentAuthorizationId == null)
            .OrderByDescending(s => s.LastSeenAt).Take(Most)
            .Select(s => new AccountSessionDto(s.Id.ToString(), SessionKinds.Browser, s.Id == currentSession, s.CreatedAt, s.LastSeenAt, s.ExpiresAt, s.UserAgent, s.Ip))
            .ToListAsync(cancellationToken), cancellationToken: cancellationToken);
        foreach (AppSignIn signIn in await AppSignInsAsync(accountId, cancellationToken))
        {
            sessions.Add(new AccountSessionDto(signIn.AuthorizationId, signIn.Kind, signIn.AuthorizationId == currentAuthorization, signIn.CreatedAt, signIn.LastSeenAt,
                signIn.ExpiresAt, null, null));
        }

        return [.. sessions.OrderByDescending(s => s.Current).ThenByDescending(s => s.LastSeenAt ?? s.CreatedAt).Take(Most)];
    }

    /// <summary>Ends one of the person's sessions.</summary>
    public async Task EndAsync(Guid accountId, string kind, string id, CancellationToken cancellationToken = default)
    {
        if (kind == SessionKinds.Browser)
        {
            if (!Guid.TryParse(id, out Guid sessionId)
                || !await guardDb.RunAsync(db => db.WebSessions.AnyAsync(s => s.Id == sessionId && s.AccountId == accountId, cancellationToken), cancellationToken: cancellationToken))
            {
                throw new EntityNotFoundException("There's no such session of yours.");
            }

            await web.EndAsync(sessionId, "ended", cancellationToken);
            return;
        }

        if (await authorizations.FindByIdAsync(id, cancellationToken) is not { } authorization
            || await authorizations.GetSubjectAsync(authorization, cancellationToken) != accountId.ToString()
            || await authorizations.GetApplicationIdAsync(authorization, cancellationToken) is not { } appId
            || await KindOfAsync(appId, cancellationToken) != kind)
        {
            throw new EntityNotFoundException("There's no such sign-in of yours.");
        }

        await RevokeAsync(authorization, cancellationToken);
    }

    /// <summary>
    /// The phone app or a script revoked its refresh token at the token endpoint (signing out): its whole sign-in ends,
    /// with its other tokens and the web views it opened. Anything else's (an app the person allowed) is left as it is.
    /// </summary>
    public async Task EndSignInAsync(string authorizationId, CancellationToken cancellationToken = default)
    {
        if (await KindOfSignInAsync(authorizationId, cancellationToken) is not null && await authorizations.FindByIdAsync(authorizationId, cancellationToken) is { } authorization)
        {
            await RevokeAsync(authorization, cancellationToken);
        }
    }

    /// <summary>Ends the session or sign-in a request came with: a browser signing out, or the phone app signing out.</summary>
    public async Task EndCurrentAsync(Guid accountId, Guid? currentSession, string? currentAuthorization, CancellationToken cancellationToken = default)
    {
        if (currentSession is { } session)
        {
            await web.EndAsync(session, "signed-out", cancellationToken);
        }
        else if (currentAuthorization is not null && await KindOfSignInAsync(currentAuthorization, cancellationToken) is { } kind)
        {
            await EndAsync(accountId, kind, currentAuthorization, cancellationToken);
        }
    }

    /// <summary>
    /// Ends every session of the person but the one kept (the request's own): signing out everywhere else, or, with
    /// nothing kept, an admin locking the account.
    /// </summary>
    public async Task<SessionsEndedDto> EndEverywhereAsync(Guid accountId, Guid? keepSession, string? keepAuthorization, string reason, CancellationToken cancellationToken = default)
    {
        // From the phone app's web view, the app's sign-in is this one too.
        keepAuthorization ??= await OpenedByAsync(keepSession, cancellationToken);
        int browsers = await web.EndAllAsync(accountId, reason, keepSession, keepAuthorization, cancellationToken);
        int apps = 0;
        foreach (AppSignIn signIn in await AppSignInsAsync(accountId, cancellationToken))
        {
            if (signIn.AuthorizationId != keepAuthorization && await authorizations.FindByIdAsync(signIn.AuthorizationId, cancellationToken) is { } authorization)
            {
                await RevokeAsync(authorization, cancellationToken);
                apps++;
            }
        }

        await audit.WriteAsync(SecurityAuditTypes.SessionsEnded, new AuditTarget("Account", accountId, null), new { browsers, apps, reason }, cancellationToken);
        return new SessionsEndedDto(browsers, apps);
    }

    /// <summary>
    /// The phone app's and scripts' live sign-ins: a permission with a refresh token still good. With rolling refresh
    /// tokens, the first token says when it signed in, the newest when it last refreshed.
    /// </summary>
    private async Task<List<AppSignIn>> AppSignInsAsync(Guid accountId, CancellationToken cancellationToken)
    {
        Dictionary<string, string?> kinds = [];
        Dictionary<string, Seen> signIns = [];
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await foreach (object token in tokens.FindBySubjectAsync(accountId.ToString(), cancellationToken))
        {
            if (await tokens.GetAuthorizationIdAsync(token, cancellationToken) is not { } authorizationId
                || await tokens.GetApplicationIdAsync(token, cancellationToken) is not { } appId)
            {
                continue;
            }

            if (!kinds.TryGetValue(appId, out string? kind))
            {
                kinds[appId] = kind = await KindOfAsync(appId, cancellationToken);
            }

            if (kind is null)
            {
                continue;
            }

            DateTime created = (await tokens.GetCreationDateAsync(token, cancellationToken))?.UtcDateTime ?? DateTime.MinValue;
            if (!signIns.TryGetValue(authorizationId, out Seen? seen))
            {
                signIns[authorizationId] = seen = new Seen(kind, created);
            }

            seen.First = created < seen.First ? created : seen.First;
            seen.Last = created > seen.Last ? created : seen.Last;
            if (await tokens.GetTypeAsync(token, cancellationToken) == TokenTypeIdentifiers.RefreshToken
                && await tokens.GetStatusAsync(token, cancellationToken) == Statuses.Valid
                && await tokens.GetExpirationDateAsync(token, cancellationToken) is { } expires && expires > now
                && (seen.Expires is null || expires.UtcDateTime > seen.Expires))
            {
                seen.Expires = expires.UtcDateTime;
            }
        }

        // Live while a refresh token is still good.
        return [.. signIns.Where(s => s.Value.Expires is not null).Select(s => new AppSignIn(s.Key, s.Value.Kind, s.Value.First, s.Value.Last, s.Value.Expires))];
    }

    private sealed class Seen(string kind, DateTime at)
    {
        public string Kind { get; } = kind;
        public DateTime First { get; set; } = at;
        public DateTime Last { get; set; } = at;
        public DateTime? Expires { get; set; }
    }

    /// <summary>The phone app's sign-in a web view's session was opened by; null for a browser's own.</summary>
    private Task<string?> OpenedByAsync(Guid? sessionId, CancellationToken cancellationToken) =>
        sessionId is { } id
            ? guardDb.RunAsync(db => db.WebSessions.Where(s => s.Id == id).Select(s => s.ParentAuthorizationId).FirstOrDefaultAsync(cancellationToken), cancellationToken: cancellationToken)
            : Task.FromResult<string?>(null);

    /// <summary>What a sign-in (an OpenIddict permission) is: phone, script, or null for anything else.</summary>
    public async Task<string?> KindOfSignInAsync(string authorizationId, CancellationToken cancellationToken = default) =>
        await authorizations.FindByIdAsync(authorizationId, cancellationToken) is { } authorization
        && await authorizations.GetStatusAsync(authorization, cancellationToken) == Statuses.Valid
        && await authorizations.GetApplicationIdAsync(authorization, cancellationToken) is { } appId
            ? await KindOfAsync(appId, cancellationToken)
            : null;

    /// <summary>Phone for the app, script for web; null for any other app (OAuth apps are listed apart).</summary>
    private async Task<string?> KindOfAsync(string applicationId, CancellationToken cancellationToken) =>
        await applications.FindByIdAsync(applicationId, cancellationToken) is { } app
            ? await applications.GetClientIdAsync(app, cancellationToken) is { } clientId
                ? clientId == options.Value.Clients.Mobile ? SessionKinds.Phone : clientId == options.Value.Clients.Web ? SessionKinds.Script : null
                : null
            : null;

    /// <summary>A sign-in ends: its permission and tokens are revoked, and the web views it opened end with it.</summary>
    private async Task RevokeAsync(object authorization, CancellationToken cancellationToken)
    {
        string id = (await authorizations.GetIdAsync(authorization, cancellationToken))!;
        await authorizations.TryRevokeAsync(authorization, cancellationToken);
        await tokens.RevokeByAuthorizationIdAsync(id, cancellationToken);
        await web.EndOpenedByAsync(id, cancellationToken);
    }
}

/// <summary>
/// The phone app (or a script) signing out revokes its refresh token at the token endpoint (RFC 7009): its whole sign-in
/// ends, with its other tokens and the web views it opened, not just the one token.
/// </summary>
public sealed class EndSignInOnRevocation(AccountSessions sessions) : OpenIddict.Server.IOpenIddictServerHandler<OpenIddict.Server.OpenIddictServerEvents.HandleRevocationRequestContext>
{
    public static OpenIddict.Server.OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddict.Server.OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddict.Server.OpenIddictServerEvents.HandleRevocationRequestContext>()
            .UseScopedHandler<EndSignInOnRevocation>()
            .SetOrder(OpenIddict.Server.OpenIddictServerHandlers.Revocation.RevokeToken.Descriptor.Order + 1_000)
            .SetType(OpenIddict.Server.OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(OpenIddict.Server.OpenIddictServerEvents.HandleRevocationRequestContext context)
    {
        if (context.GenericTokenPrincipal?.GetTokenType() == TokenTypeIdentifiers.RefreshToken && context.GenericTokenPrincipal.GetAuthorizationId() is { } authorizationId)
        {
            await sessions.EndSignInAsync(authorizationId, context.CancellationToken);
        }
    }
}

/// <summary>
/// An access token made before the site renamed its claims and scopes reads as made under today's names
/// (<see cref="GuardNames.Former"/>), before anything reads its claims: it keeps its limits until it expires. One with a
/// session, mode, token or limit claim under a name Guard doesn't know is refused.
/// </summary>
public sealed class TokenNamesOfToday(Microsoft.Extensions.Options.IOptions<GuardNames> names)
    : OpenIddict.Validation.IOpenIddictValidationHandler<OpenIddict.Validation.OpenIddictValidationEvents.ProcessAuthenticationContext>
{
    public static OpenIddict.Validation.OpenIddictValidationHandlerDescriptor Descriptor { get; } =
        OpenIddict.Validation.OpenIddictValidationHandlerDescriptor.CreateBuilder<OpenIddict.Validation.OpenIddictValidationEvents.ProcessAuthenticationContext>()
            .UseSingletonHandler<TokenNamesOfToday>()
            .SetOrder(OpenIddict.Validation.OpenIddictValidationHandlers.ValidateAccessToken.Descriptor.Order + 1_000)
            .SetType(OpenIddict.Validation.OpenIddictValidationHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(OpenIddict.Validation.OpenIddictValidationEvents.ProcessAuthenticationContext context)
    {
        if (context.AccessTokenPrincipal is { } principal)
        {
            if (names.Value.Current(principal, OpenIddictConstants.Claims.Private.Scope) is { } current)
            {
                context.AccessTokenPrincipal = current;
            }
            else
            {
                context.Reject(OpenIddictConstants.Errors.InvalidToken, "The token carries a claim this site doesn't know.");
            }
        }

        return ValueTask.CompletedTask;
    }
}
