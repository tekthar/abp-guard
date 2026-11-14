using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using AbpGuard.Domain;
using AbpGuard.Services;
using OpenIddict.Abstractions;
using Microsoft.Extensions.Options;

namespace AbpGuard.Controllers;

public sealed record SessionStartInput(string? Username, string? Password);

/// <summary>A step-up: the password again, and a code of the person's second factor when they have one.</summary>
public sealed record SessionStepUpInput(string? Password, string? Method = null, string? Code = null);

/// <summary>The second step of a sign-in: the ticket, and a code of the method (<c>app</c>, <c>recovery</c>).</summary>
public sealed record SessionSecondFactorInput(string? Ticket, string? Method, string? Code);

/// <summary>
/// A browser just signed in: its account and preferences, when the session ends unless it's used, and when the person
/// proved who they are. <paramref name="SecondFactorOffered"/>: a group of theirs offers a second factor they haven't set up.
/// </summary>
public sealed record SessionDto(AccountDto Account, PreferencesDto Preferences, DateTime ExpiresAt, DateTime AuthTime, bool SecondFactorOffered = false);

/// <summary>When a step-up passed: the session's new proof of who the person is.</summary>
public sealed record SessionStepUpDto(DateTime AuthTime);

/// <summary>The phone app's code for a web view: open <c>/api/guard/session/handoff?code=…&amp;next=…</c> before it expires.</summary>
public sealed record SessionHandoffDto(string Code, DateTime ExpiresAt);

/// <summary>
/// The web's sign-in, sign-out and step-up. Signing in checks the password with the account's directory, as
/// the token endpoint does, and answers with the session's cookies: <c>guard_session</c> (only the server reads it) and
/// <c>guard_csrf</c>, which the page sends back as the X-Guard-Csrf header on every request that changes something. Phones
/// and tools keep bearer tokens from the token endpoint.
/// </summary>
[Route("api/guard/session")]
public class SessionController(AuthService auth, WebSessions sessions, GuardDb guardDb, IGuardSiteDefaults siteDefaults, IOptions<GuardOptions> options,
    Services.TwoFactor.SecondFactors secondFactors)
    : GuardControllerBase
{
    /// <summary>The web's client, in a sign-in ticket.</summary>
    public const string WebClient = "web";

    /// <summary>
    /// Signs in with a username and password; a session this browser had before ends. When the person's groups ask for a
    /// second factor, or they set one up, the answer is 401 <c>second_factor_required</c> with <c>secondFactor</c>: a
    /// ticket for <c>POST /api/guard/session/second-factor</c> and the methods it takes.
    /// </summary>
    [HttpPost]
    [AllowAnonymous]
    [ProducesResponseType<SessionDto>(200)]
    public async Task<IActionResult> Start([FromBody] SessionStartInput input, CancellationToken cancellationToken)
    {
        if (WebSessionHandler.IsCrossSite(Request, options.Value.PublicUrl))
        {
            return Error(403, "cross_site_request", "This request came from another site and was refused.");
        }

        if (input.Username is not { Length: > 0 } username || input.Password is not { } password)
        {
            return Error(400, "invalid_request", "Expected a JSON body with username and password.");
        }

        LoginResult result = await auth.LoginAsync(username, password, ClientIp, cancellationToken);
        if (!result.Succeeded)
        {
            return result.ErrorCode switch
            {
                "too_many_attempts" => Error(429, "too_many_attempts", "Too many failed attempts. Try again in 15 minutes."),
                "account_merged" => Error(401, "account_merged", $"This account was merged into {result.MergedInto}. Sign in as {result.MergedInto}."),
                _ => Error(401, "invalid_credentials", "The username or password is incorrect."),
            };
        }

        if (await secondFactors.ChallengeAsync(result.Account!.Id, WebClient, null, ClientIp, cancellationToken) is { } challenge)
        {
            return new ObjectResult(new
            {
                error = new { code = "second_factor_required", message = challenge.Enrol ? "Set up a second factor to sign in." : "Enter the code of your second factor." },
                secondFactor = challenge,
            }) { StatusCode = 401 };
        }

        return Ok(await StartSessionAsync(result.Account!.Id, cancellationToken));
    }

    /// <summary>
    /// The second step of a sign-in: the ticket from the password, and a code of the method (<c>app</c>, or a
    /// <c>recovery</c> code); or the ticket alone, once a second factor was set up with it. Answers as signing in does.
    /// </summary>
    [HttpPost("second-factor")]
    [GuardFeature(nameof(GuardFeatures.TwoFactor))]
    [AllowAnonymous]
    [ProducesResponseType<SessionDto>(200)]
    public async Task<IActionResult> SecondFactor([FromBody] SessionSecondFactorInput input, CancellationToken cancellationToken)
    {
        if (WebSessionHandler.IsCrossSite(Request, options.Value.PublicUrl))
        {
            return Error(403, "cross_site_request", "This request came from another site and was refused.");
        }

        if (input.Ticket is not { Length: > 0 } ticket)
        {
            return Error(400, "invalid_request", "Expected a JSON body with the sign-in's ticket and a code.");
        }

        Services.TwoFactor.SecondStepResult step = await secondFactors.PassAsync(ticket, input.Method, input.Code, WebClient, ClientIp, cancellationToken);
        return step.Passed is { } passed
            ? Ok(await StartSessionAsync(passed.AccountId, cancellationToken))
            : SecondStepError(step.Error);
    }

    /// <summary>The answers a failed second step gives.</summary>
    public static ObjectResult SecondStepError(string? error) => error switch
    {
        "too_many_attempts" => Error(429, "too_many_attempts", "Too many wrong codes. Try again in 15 minutes."),
        "second_factor_failed" => Error(400, "second_factor_failed", "The code is incorrect."),
        _ => Error(401, "ticket_expired", "This sign-in has expired. Sign in again."),
    };

    private async Task<SessionDto> StartSessionAsync(Guid accountId, CancellationToken cancellationToken)
    {
        await EndPreviousAsync(cancellationToken);
        (WebSession session, string secret) = await sessions.StartAsync(accountId, Request.Headers.UserAgent.ToString(), ClientIp, cancellationToken: cancellationToken);
        WebSessionHandler.Issue(HttpContext, secret, embedded: false);
        Services.TwoFactor.MySecondFactorsDto mine = await secondFactors.ListAsync(accountId, cancellationToken);
        return await guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.AsNoTracking().FirstAsync(a => a.Id == session.AccountId, cancellationToken);
            string directory = await db.Directories.Where(d => d.Id == account.DirectoryId).Select(d => d.Name).FirstOrDefaultAsync(cancellationToken) ?? "?";
            return new SessionDto(AccountDto.From(account, directory), PreferencesDto.For(account, siteDefaults), session.ExpiresAt, session.AuthTime,
                mine is { Mode: Domain.TwoFactorModes.Optional, Factors.Count: 0, Disabled: false });
        }, cancellationToken: cancellationToken);
    }

    /// <summary>Signs out: the session ends and the browser forgets its cookies.</summary>
    [HttpDelete]
    [AllowAnonymous]
    public async Task<NoContentResult> End(CancellationToken cancellationToken)
    {
        if (Guid.TryParse(User.FindFirst(WebSessionHandler.SessionIdClaim)?.Value, out Guid sessionId))
        {
            await sessions.EndAsync(sessionId, "signed-out", cancellationToken);
        }

        WebSessionHandler.Clear(HttpContext);
        return NoContent();
    }

    /// <summary>
    /// A step-up: the password again, checked by the account's directory, marks the session for the site's
    /// step-up minutes. A wrong password answers 400 and the session goes on; too many end it (401, cookies cleared).
    /// </summary>
    [HttpPost("step-up")]
    [Authorize]
    [ProducesResponseType<SessionStepUpDto>(200)]
    public async Task<IActionResult> StepUp([FromBody] SessionStepUpInput input, CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(User.FindFirst(WebSessionHandler.SessionIdClaim)?.Value, out Guid sessionId))
        {
            return Error(400, "not_a_session", "Only a browser's session steps up here.");
        }

        if (input.Password is not { Length: > 0 } password)
        {
            return Error(400, "invalid_request", "Enter your password.");
        }

        StepUpResult result = await auth.StepUpAsync(CurrentAccountId, password, ClientIp, cancellationToken);
        if (!result.Succeeded && result.EndSession)
        {
            await sessions.EndAsync(sessionId, "step-up", cancellationToken);
            WebSessionHandler.Clear(HttpContext);
            return Error(401, "session_ended", "Too many wrong passwords: the session has ended. Sign in again.");
        }

        if (result.Blocked)
        {
            return Error(429, "too_many_attempts", "Too many failed attempts. Try again in 15 minutes.");
        }

        if (!result.Succeeded)
        {
            return Error(400, "step_up_failed", "The password is incorrect.");
        }

        // A person with a second factor proves it again too.
        if (await secondFactors.StepUpErrorAsync(CurrentAccountId, input.Method, input.Code, ClientIp, cancellationToken) is { } secondFactorError)
        {
            return secondFactorError == "second_factor_required"
                ? Error(400, "second_factor_required", "Enter the code of your second factor too.")
                : SecondStepError(secondFactorError);
        }

        return await sessions.MarkSteppedUpAsync(sessionId, cancellationToken) is { } authTime
            ? Ok(new SessionStepUpDto(authTime))
            : Error(401, "session_ended", "Your session has ended. Sign in again.");
    }

    /// <summary>
    /// The phone app hands its sign-in to a web view: with its bearer token it gets a code that's good once, for
    /// 30 seconds, which the web view opens below. Only the app asks: not a browser, a script or another app.
    /// </summary>
    [HttpPost("handoff")]
    [GuardFeature(nameof(GuardFeatures.Handoff))]
    [Authorize]
    [ProducesResponseType<SessionHandoffDto>(200)]
    public async Task<IActionResult> HandOff([FromServices] AccountSessions accountSessions, CancellationToken cancellationToken)
    {
        if (User.GetAuthorizationId() is not { } authorizationId || Acting.TokenId is not null
            || await accountSessions.KindOfSignInAsync(authorizationId, cancellationToken) != SessionKinds.Phone)
        {
            return Error(400, "not_the_app", "Only the phone app hands its sign-in to a web view.");
        }

        (string code, DateTime expiresAt) = await sessions.HandOffAsync(CurrentAccountId, authorizationId, Acting.AuthTime?.UtcDateTime ?? DateTime.UnixEpoch, cancellationToken);
        return Ok(new SessionHandoffDto(code, expiresAt));
    }

    /// <summary>
    /// The web view opens this with the app's code. The code is taken (once), a session starts for the web view, tied to
    /// the app's sign-in, and the browser goes on to <c>next</c> with the shell embedded, in the app's language
    /// (<c>lang</c>) when it says one. A used, unknown or old code goes to the sign-in page instead. The code is in an
    /// address only for these seconds: the answer is a redirect that sends no referrer and isn't kept.
    /// </summary>
    [HttpGet("handoff")]
    [GuardFeature(nameof(GuardFeatures.Handoff))]
    [AllowAnonymous]
    [AnswersItsOwnErrors] // a web view follows redirects: a refused handoff goes to sign-in, never to a JSON error
    public async Task<IActionResult> TakeHandoff([FromQuery] string? code, [FromQuery] string? next, [FromQuery] string? lang,
        CancellationToken cancellationToken)
    {
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Response.Headers.CacheControl = "no-store";
        string target = SafeNext(next);
        // A page on another site can't sign this browser in to someone else's account: the app opens the address itself.
        if (Request.Headers["Sec-Fetch-Site"].ToString() is { Length: > 0 } site && site is not ("none" or "same-origin"))
        {
            return Error(403, "cross_site_request", "This request came from another site and was refused.");
        }

        if (code is not { Length: > 0 } || await sessions.TakeHandoffAsync(code, cancellationToken) is not { } handoff)
        {
            return LocalRedirect("/login?next=" + Uri.EscapeDataString(target));
        }

        await EndPreviousAsync(cancellationToken);
        (_, string secret) = await sessions.StartAsync(handoff.AccountId, Request.Headers.UserAgent.ToString(), ClientIp, handoff.AuthorizationId, handoff.AuthTime,
            cancellationToken);
        WebSessionHandler.Issue(HttpContext, secret, embedded: true);
        // A language tag ("ar", "pt-BR"); the web matches it against the site's languages, as it does its switcher's.
        if (lang is { Length: > 0 and <= 35 } && lang.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'))
        {
            WebSessionHandler.IssueLanguage(HttpContext, lang);
        }

        // SafeNext keeps only a path of this site; LocalRedirect refuses anything else as well.
        return LocalRedirect(target);
    }

    /// <summary>Where to go on to: a page of this site (a path), never another site.</summary>
    public static string SafeNext(string? next) =>
        next is { Length: > 0 } && next[0] == '/' && !next.StartsWith("//", StringComparison.Ordinal) && !next.StartsWith("/\\", StringComparison.Ordinal)
        && !next.Any(char.IsControl)
            ? next
            : "/";

    /// <summary>A session this browser had before ends: one browser, one session.</summary>
    private async Task EndPreviousAsync(CancellationToken cancellationToken)
    {
        if (Request.Cookies[WebSessionHandler.Names(HttpContext).Session] is { Length: > 0 } before && await sessions.FindAsync(before, cancellationToken) is { } previous)
        {
            await sessions.EndAsync(previous.Info.Id, "signed-out", cancellationToken);
        }
    }

    internal static ObjectResult Error(int status, string code, string message) => new(new { error = new { code, message } }) { StatusCode = status };
}

/// <summary>
/// Where the person is signed in: browsers, the phone app, scripts. Each can be ended, or all but this one
/// ("sign out everywhere else"). Ending this browser's session here is signing out.
/// </summary>
[Route("api/guard/me/sessions")]
[Authorize]
public class MySessionsController(AccountSessions sessions) : GuardControllerBase
{
    [HttpGet]
    public Task<List<AccountSessionDto>> List(CancellationToken cancellationToken) =>
        sessions.ListAsync(CurrentAccountId, CurrentSession, User.GetAuthorizationId(), cancellationToken);

    /// <summary>Ends the request's own session: a browser (or a web view) signing out, or the phone app signing out, its web views with it.</summary>
    [HttpDelete("current")]
    public async Task<NoContentResult> EndCurrent(CancellationToken cancellationToken)
    {
        await sessions.EndCurrentAsync(CurrentAccountId, CurrentSession, User.GetAuthorizationId(), cancellationToken);
        if (CurrentSession is not null)
        {
            WebSessionHandler.Clear(HttpContext);
        }

        return NoContent();
    }

    [HttpDelete("{kind}/{id}")]
    public async Task<NoContentResult> End(string kind, string id, CancellationToken cancellationToken)
    {
        await sessions.EndAsync(CurrentAccountId, kind, id, cancellationToken);
        if (kind == SessionKinds.Browser && CurrentSession?.ToString() == id)
        {
            WebSessionHandler.Clear(HttpContext);
        }

        return NoContent();
    }

    /// <summary>Signs out everywhere else: every other browser, the phone app and scripts; this one goes on.</summary>
    [HttpPost("everywhere")]
    public Task<SessionsEndedDto> EndEverywhere(CancellationToken cancellationToken) =>
        sessions.EndEverywhereAsync(CurrentAccountId, CurrentSession, User.GetAuthorizationId(), "everywhere", cancellationToken);

    private Guid? CurrentSession => Guid.TryParse(User.FindFirst(WebSessionHandler.SessionIdClaim)?.Value, out Guid id) ? id : null;
}
