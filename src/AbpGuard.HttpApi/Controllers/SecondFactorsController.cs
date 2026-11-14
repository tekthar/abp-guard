using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AbpGuard.Services.TwoFactor;
using AbpGuard.Acting;

namespace AbpGuard.Controllers;

/// <summary>Setting up a second factor at sign-in: the ticket the password gave.</summary>
public sealed record SecondFactorTicketInput(string? Ticket);

/// <summary>The authenticator app's first code; with the sign-in's ticket when setting up at sign-in.</summary>
public sealed record SecondFactorConfirmInput(string? Code, string? Ticket = null);

/// <summary>New recovery codes, shown this once.</summary>
public sealed record RecoveryCodesDto(List<string> RecoveryCodes);

/// <summary>A code to send for a sign-in's second step: its ticket, and how (<c>email</c>, a channel's key).</summary>
public sealed record SecondFactorSendInput(string? Ticket, string? Method);

/// <summary>A code to send to someone signed in, for a step-up.</summary>
public sealed record MySecondFactorSendInput(string? Method);

/// <summary>
/// Sending a second step's code by email, SMS or WhatsApp, with the ticket the password gave: six digits, for
/// ten minutes, to the address the site has for the person. Three a sign-in, five a person in 15 minutes.
/// </summary>
[Route("api/guard/second-factor")]
[AllowAnonymous]
[GuardFeature(nameof(GuardFeatures.TwoFactor))]
public class SecondFactorCodesController(SecondFactors secondFactors) : GuardControllerBase
{
    [HttpPost("send")]
    [ProducesResponseType<CodeSentDto>(200)]
    public async Task<IActionResult> Send([FromBody] SecondFactorSendInput input, CancellationToken cancellationToken) =>
        input.Ticket is { Length: > 0 } ticket
            ? Answer(await secondFactors.SendForTicketAsync(ticket, input.Method, ClientIp, cancellationToken))
            : SessionController.Error(401, "ticket_expired", "This sign-in has expired. Sign in again.");

    /// <summary>The answers sending a code gives.</summary>
    public static IActionResult Answer(SendCodeResult result) => result switch
    {
        { Sent: { } sent } => new OkObjectResult(sent),
        { Error: "ticket_expired" } => SessionController.Error(401, "ticket_expired", "This sign-in has expired. Sign in again."),
        { Error: "too_many_attempts" } => SessionController.Error(429, "too_many_attempts", "Too many codes sent. Try again in 15 minutes."),
        { Error: "unreachable" } => SessionController.Error(400, "unreachable", "There's no address to send that code to. Try another way."),
        { Error: "not_sent" } => SessionController.Error(502, "not_sent", "The code couldn't be sent. Try another way, or again later."),
        _ => SessionController.Error(400, "method_not_allowed", "This site doesn't send codes that way."),
    };
}

/// <summary>
/// Setting up a second factor at sign-in, when a group of the person's requires one and they have none yet:
/// the ticket from the password, then the app's first code. The ticket then passes the second step with no code
/// (<c>POST /api/guard/session/second-factor</c>, or the token endpoint's <c>urn:abpguard:grant-type:second-factor</c>).
/// </summary>
[Route("api/guard/second-factor/enrol")]
[AllowAnonymous]
[GuardFeature(nameof(GuardFeatures.TwoFactor))]
public class SecondFactorEnrolmentController(SecondFactors secondFactors) : GuardControllerBase
{
    /// <summary>Starts setting up the authenticator app: its secret, address and QR code.</summary>
    [HttpPost("app")]
    [ProducesResponseType<AppEnrolmentDto>(200)]
    public async Task<IActionResult> StartApp([FromBody] SecondFactorTicketInput input, CancellationToken cancellationToken) =>
        await AccountAsync(input.Ticket, cancellationToken) is { } accountId
            ? Ok(await secondFactors.StartAppAsync(accountId, cancellationToken))
            : TicketRefused();

    /// <summary>Finishes with the app's first code: the recovery codes, shown once, and the ticket passes the second step.</summary>
    [HttpPost("app/confirm")]
    [ProducesResponseType<SecondFactorEnrolledDto>(200)]
    public async Task<IActionResult> ConfirmApp([FromBody] SecondFactorConfirmInput input, CancellationToken cancellationToken)
    {
        if (await AccountAsync(input.Ticket, cancellationToken) is not { } accountId)
        {
            return TicketRefused();
        }

        if (await secondFactors.FinishAppAsync(accountId, input.Code, cancellationToken) is not { } enrolled)
        {
            await secondFactors.SpendTicketTryAsync(input.Ticket!, cancellationToken);
            return SessionController.Error(400, "second_factor_failed", "The code is incorrect. Check the time on your phone, and enter the code it shows now.");
        }

        await secondFactors.ProveTicketAsync(input.Ticket!, cancellationToken);
        return Ok(enrolled);
    }

    private Task<Guid?> AccountAsync(string? ticket, CancellationToken cancellationToken) =>
        ticket is { Length: > 0 } ? secondFactors.TicketAccountAsync(ticket, cancellationToken) : Task.FromResult<Guid?>(null);

    private static ObjectResult TicketRefused() => SessionController.Error(401, "ticket_expired", "This sign-in has expired. Sign in again.");
}

/// <summary>
/// A person's own second factors: what their groups ask, the factors they have, setting up the authenticator
/// app, removing one (not the last while a group requires one) and new recovery codes. Changing them needs a step-up.
/// </summary>
[Route("api/guard/me/second-factors")]
[Authorize]
[GuardFeature(nameof(GuardFeatures.TwoFactor))]
public class MySecondFactorsController(SecondFactors secondFactors) : GuardControllerBase
{
    [HttpGet]
    public Task<MySecondFactorsDto> Get(CancellationToken cancellationToken) => secondFactors.ListAsync(CurrentAccountId, cancellationToken);

    /// <summary>Starts setting up the authenticator app: its secret, address and QR code.</summary>
    [HttpPost("app")]
    [StepUp]
    public Task<AppEnrolmentDto> StartApp(CancellationToken cancellationToken) => secondFactors.StartAppAsync(CurrentAccountId, cancellationToken);

    /// <summary>Finishes with the app's first code; the first second factor comes with recovery codes, shown once.</summary>
    [HttpPost("app/confirm")]
    [StepUp]
    [ProducesResponseType<SecondFactorEnrolledDto>(200)]
    public async Task<IActionResult> ConfirmApp([FromBody] SecondFactorConfirmInput input, CancellationToken cancellationToken) =>
        await secondFactors.FinishAppAsync(CurrentAccountId, input.Code, cancellationToken) is { } enrolled
            ? Ok(enrolled)
            : SessionController.Error(400, "second_factor_failed", "The code is incorrect. Check the time on your phone, and enter the code it shows now.");

    [HttpDelete("{id:guid}")]
    [StepUp]
    public async Task<NoContentResult> Remove(Guid id, CancellationToken cancellationToken)
    {
        await secondFactors.RemoveAsync(CurrentAccountId, id, cancellationToken);
        return NoContent();
    }

    /// <summary>Sends a code by email or a channel, for a step-up (the person has no app, or not at hand).</summary>
    [HttpPost("send")]
    [ProducesResponseType<CodeSentDto>(200)]
    public async Task<IActionResult> Send([FromBody] MySecondFactorSendInput input, CancellationToken cancellationToken) =>
        SecondFactorCodesController.Answer(await secondFactors.SendForAccountAsync(CurrentAccountId, input.Method, ClientIp, cancellationToken));

    /// <summary>Ten new recovery codes in place of the old ones.</summary>
    [HttpPost("recovery-codes")]
    [StepUp]
    public async Task<RecoveryCodesDto> RenewRecoveryCodes(CancellationToken cancellationToken) =>
        new(await secondFactors.RenewRecoveryCodesAsync(CurrentAccountId, cancellationToken));
}
