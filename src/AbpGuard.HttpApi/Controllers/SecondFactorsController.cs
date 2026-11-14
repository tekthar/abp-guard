using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using AbpGuard.Services.TwoFactor;
using AbpGuard.Acting;
using OpenIddict.Abstractions;

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

    /// <summary>
    /// Starts setting up a passkey at sign-in: the creation options (the browser's <c>PublicKeyCredentialCreationOptionsJSON</c>),
    /// whose challenge is good once, for five minutes, for this ticket.
    /// </summary>
    [HttpPost("passkey/options")]
    public async Task<IActionResult> PasskeyOptions([FromBody] SecondFactorTicketInput input, CancellationToken cancellationToken) =>
        input.Ticket is { Length: > 0 } ticket && await secondFactors.EnrolPasskeyOptionsAsync(ticket, cancellationToken) is { } json
            ? Content(json, "application/json")
            : TicketRefused();

    /// <summary>
    /// Finishes setting up a passkey at sign-in with the device's answer: the passkey, the recovery codes (shown once), and
    /// the ticket passes the second step. A refused answer is <c>passkey_rejected</c> (a try less), or <c>passkey_exists</c>.
    /// </summary>
    [HttpPost("passkey")]
    [ProducesResponseType<PasskeyAddedDto>(200)]
    public async Task<IActionResult> Passkey([FromBody] PasskeyEnrolInput input, CancellationToken cancellationToken)
    {
        if (input.Ticket is not { Length: > 0 } ticket)
        {
            return TicketRefused();
        }

        PasskeyAddResult added = await secondFactors.EnrolPasskeyAsync(ticket, input.Name, input.Credential, cancellationToken);
        return added.Added is { } passkey ? Ok(passkey) : PasskeyError(added.Error);
    }

    /// <summary>The answers adding a passkey gives when it's refused.</summary>
    public static ObjectResult PasskeyError(string? error) => error switch
    {
        "ticket_expired" => TicketRefused(),
        Passkeys.Exists => SessionController.Error(400, Passkeys.Exists, "That device's passkey is registered already."),
        _ => SessionController.PasskeyRejected(),
    };

    private Task<Guid?> AccountAsync(string? ticket, CancellationToken cancellationToken) =>
        ticket is { Length: > 0 } ? secondFactors.TicketAccountAsync(ticket, cancellationToken) : Task.FromResult<Guid?>(null);

    private static ObjectResult TicketRefused() => SessionController.Error(401, "ticket_expired", "This sign-in has expired. Sign in again.");
}

/// <summary>A passkey set up at sign-in: the ticket, the name the person gives it, and the device's answer (its <c>toJSON()</c>).</summary>
public sealed record PasskeyEnrolInput(string? Ticket, string? Name, JsonElement? Credential);

/// <summary>A passkey added by someone signed in: its name and the device's answer.</summary>
public sealed record PasskeyInput(string? Name, JsonElement? Credential);

/// <summary>A passkey's new name.</summary>
public sealed record PasskeyNameInput(string? Name);

/// <summary>
/// A person's own passkeys: the creation options, adding one with the device's answer, and renaming one. Removing one is
/// the second factors' (<c>DELETE api/guard/me/second-factors/{id}</c>), and they're listed there beside the app.
/// </summary>
[Route("api/guard/me/passkeys")]
[Authorize]
[GuardFeature(nameof(GuardFeatures.TwoFactor))]
public class MyPasskeysController(SecondFactors secondFactors) : GuardControllerBase
{
    /// <summary>
    /// The creation options (the browser's <c>PublicKeyCredentialCreationOptionsJSON</c>), for this session or sign-in. Asks
    /// the step-up adding a factor needs (<see cref="FactorStepUps"/>) before the device's prompt, not after it.
    /// </summary>
    [HttpPost("options")]
    public async Task<IActionResult> Options(CancellationToken cancellationToken)
    {
        if (Binding() is not { } binding)
        {
            return SessionController.Error(400, "not_a_session", "Only a browser's or the app's sign-in adds a passkey.");
        }

        await FactorStepUps.EnsureMayAddAsync(HttpContext, secondFactors, CurrentAccountId, cancellationToken);
        return Content(await secondFactors.PasskeyOptionsAsync(CurrentAccountId, binding, cancellationToken), "application/json");
    }

    /// <summary>Adds a passkey with the device's answer: the factor, and recovery codes (shown once) when it's the person's first.</summary>
    [HttpPost]
    [ProducesResponseType<PasskeyAddedDto>(200)]
    public async Task<IActionResult> Add([FromBody] PasskeyInput input, CancellationToken cancellationToken)
    {
        if (Binding() is not { } binding)
        {
            return SessionController.Error(400, "not_a_session", "Only a browser's or the app's sign-in adds a passkey.");
        }

        await FactorStepUps.EnsureMayAddAsync(HttpContext, secondFactors, CurrentAccountId, cancellationToken);
        PasskeyAddResult added = await secondFactors.AddPasskeyAsync(CurrentAccountId, binding, input.Name, input.Credential, cancellationToken);
        return added.Added is { } passkey ? Ok(passkey) : SecondFactorEnrolmentController.PasskeyError(added.Error);
    }

    [HttpPut("{id:guid}")]
    public Task<SecondFactorDto> Rename(Guid id, [FromBody] PasskeyNameInput input, CancellationToken cancellationToken) =>
        secondFactors.RenamePasskeyAsync(CurrentAccountId, id, input.Name, cancellationToken);

    /// <summary>What a ceremony belongs to: the browser's session, else the app's sign-in; a personal access token has neither.</summary>
    private string? Binding() =>
        Guid.TryParse(User.FindFirst(Services.WebSessionHandler.SessionIdClaim)?.Value, out Guid session) ? Passkeys.SessionBinding(session)
        : Acting.TokenId is null && User.GetAuthorizationId() is { Length: > 0 } authorization ? Passkeys.AppBinding(authorization)
        : null;
}

/// <summary>
/// The step-ups a person's own second factors ask. Adding one (a passkey, the app) needs a strong step-up once they have a
/// strong factor, where a sign-in with a recovery code counts too, so someone who lost their device can set up a new one;
/// their first needs a password-level one, as a phished password can't make itself strong. Removing their last strong
/// factor needs a strong step-up; the rest are the <c>factors</c> category's.
/// </summary>
public static class FactorStepUps
{
    public static async Task EnsureMayAddAsync(HttpContext http, SecondFactors secondFactors, Guid accountId, CancellationToken cancellationToken)
    {
        bool strong = !secondFactors.Disabled && await secondFactors.HasStrongAsync(accountId, cancellationToken);
        await http.RequestServices.GetRequiredService<StepUpGuard>().EnsureAtAsync(StepUpCategories.Factors, strong ? StepUpLevels.Strong : StepUpLevels.Password,
            recoverySignInCounts: strong, cancellationToken);
    }

    public static async Task EnsureMayRemoveAsync(HttpContext http, SecondFactors secondFactors, Guid accountId, Guid factorId, CancellationToken cancellationToken)
    {
        StepUpGuard guard = http.RequestServices.GetRequiredService<StepUpGuard>();
        await (!secondFactors.Disabled && await secondFactors.IsLastStrongAsync(accountId, factorId, cancellationToken) == true
            ? guard.EnsureAtAsync(StepUpCategories.Factors, StepUpLevels.Strong, cancellationToken: cancellationToken)
            : guard.EnsureAsync(StepUpCategories.Factors, cancellationToken));
    }
}

/// <summary>
/// A person's own second factors: what their groups ask, the factors they have (passkeys and the app), setting up the
/// authenticator app, removing one (not the last while a group requires one) and new recovery codes. Changing them needs a
/// step-up (<see cref="FactorStepUps"/>).
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
    public async Task<AppEnrolmentDto> StartApp(CancellationToken cancellationToken)
    {
        await FactorStepUps.EnsureMayAddAsync(HttpContext, secondFactors, CurrentAccountId, cancellationToken);
        return await secondFactors.StartAppAsync(CurrentAccountId, cancellationToken);
    }

    /// <summary>Finishes with the app's first code; the first second factor comes with recovery codes, shown once.</summary>
    [HttpPost("app/confirm")]
    [ProducesResponseType<SecondFactorEnrolledDto>(200)]
    public async Task<IActionResult> ConfirmApp([FromBody] SecondFactorConfirmInput input, CancellationToken cancellationToken)
    {
        await FactorStepUps.EnsureMayAddAsync(HttpContext, secondFactors, CurrentAccountId, cancellationToken);
        return await secondFactors.FinishAppAsync(CurrentAccountId, input.Code, cancellationToken) is { } enrolled
            ? Ok(enrolled)
            : SessionController.Error(400, "second_factor_failed", "The code is incorrect. Check the time on your phone, and enter the code it shows now.");
    }

    /// <summary>Removes one of the person's factors (the app, or a passkey): a strong step-up when it's their last strong one.</summary>
    [HttpDelete("{id:guid}")]
    public async Task<NoContentResult> Remove(Guid id, CancellationToken cancellationToken)
    {
        await FactorStepUps.EnsureMayRemoveAsync(HttpContext, secondFactors, CurrentAccountId, id, cancellationToken);
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
    [StepUp(StepUpCategories.Factors)]
    public async Task<RecoveryCodesDto> RenewRecoveryCodes(CancellationToken cancellationToken) =>
        new(await secondFactors.RenewRecoveryCodesAsync(CurrentAccountId, cancellationToken));
}
