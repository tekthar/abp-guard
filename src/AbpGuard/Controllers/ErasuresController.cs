using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AbpGuard.Acting;
using AbpGuard.Domain;
using AbpGuard.Services;
using AbpGuard.Services.Privacy;

namespace AbpGuard.Controllers;

/// <summary>
/// Erasure (PDPL's right to destruction). A person asks from the You page; a site admin erases an
/// account, or someone outside the site by an address, or declines a request with a reason; a legal hold stops any of them
/// until it's released. Erasing and releasing a hold ask for the password again; everything goes in the security log,
/// under the pseudonym once the person is erased.
/// </summary>
[Route("api/guard")]
[Authorize]
[GuardFeature(nameof(GuardFeatures.Erasure))]
public class ErasuresController(PersonalDataErasures erasures, SecurityLog audit) : GuardControllerBase
{
    // ---- the person ----

    [HttpGet("me/erasure-request")]
    public Task<ErasureDto?> MyRequest(CancellationToken cancellationToken) => erasures.LatestOfAsync(CurrentAccountId, cancellationToken);

    [HttpPost("me/erasure-request")]
    [StepUp]
    public async Task<ErasureDto> Ask([FromBody] ErasureRequestInput? input, CancellationToken cancellationToken)
    {
        ErasureDto request = await erasures.RequestAsync(CurrentAccountId, input?.Reason, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.ErasureRequested, new AuditTarget("Account", CurrentAccountId, request.About), new { request.Number }, cancellationToken);
        return request;
    }

    // ---- admins ----

    [HttpGet("privacy/erasures")]
    [Authorize(Policy = GuardPolicies.Admin)]
    public Task<List<ErasureDto>> List(CancellationToken cancellationToken) => erasures.ListAsync(cancellationToken);

    /// <summary>Declining keeps what the person asked to be erased, so it asks for the password again.</summary>
    [HttpPost("privacy/erasures/{id:guid}/decline")]
    [Authorize(Policy = GuardPolicies.Admin)]
    [StepUp]
    public async Task<ErasureDto> Decline(Guid id, [FromBody] ErasureDeclineInput input, CancellationToken cancellationToken)
    {
        string reason = (input.Reason ?? "").Trim();
        if (reason.Length is 0 or > 2000)
        {
            throw new Volo.Abp.UserFriendlyException("Say why the request is declined, in at most 2000 characters: the person is told.", "no_reason");
        }

        ErasureDto declined = await erasures.DeclineAsync(id, CurrentAccountId, reason, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.ErasureDeclined, new AuditTarget("Account", declined.AccountId, declined.About),
            new { declined.Number, reason }, cancellationToken);
        return declined;
    }

    /// <summary>Runs the stores an erasure hasn't finished: one failed, or its plugin was off.</summary>
    [HttpPost("privacy/erasures/{id:guid}/resume")]
    [Authorize(Policy = GuardPolicies.Admin)]
    [StepUp]
    public async Task<ErasureDto> Resume(Guid id, CancellationToken cancellationToken)
    {
        ErasureDto erasure = await erasures.ResumeAsync(id, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.ErasureResumed, Target(erasure), new { erasure.Number, erasure.State, erasure.Stores }, cancellationToken);
        await PublishIfDoneAsync(erasure);
        return erasure;
    }

    /// <summary>Goes on without a plugin's store the erasure waits for, with why: the plugin is gone for good, or won't run.</summary>
    [HttpPost("privacy/erasures/{id:guid}/stores/{store}/skip")]
    [Authorize(Policy = GuardPolicies.Admin)]
    [StepUp]
    public async Task<ErasureDto> SkipStore(Guid id, string store, [FromBody] ErasureDeclineInput input, CancellationToken cancellationToken)
    {
        ErasureDto erasure = await erasures.SkipStoreAsync(id, store, CurrentAccountId, input.Reason, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.ErasureStoreSkipped, Target(erasure), new { erasure.Number, store, reason = input.Reason, erasure.State },
            cancellationToken);
        await PublishIfDoneAsync(erasure);
        return erasure;
    }

    [HttpGet("accounts/{id:guid}/erasure/preview")]
    [Authorize(Policy = GuardPolicies.Admin)]
    public Task<ErasurePreviewDto> PreviewAccount(Guid id, CancellationToken cancellationToken) => erasures.PreviewAccountAsync(id, cancellationToken);

    [HttpPost("accounts/{id:guid}/erasure")]
    [Authorize(Policy = GuardPolicies.Admin)]
    [StepUp]
    public async Task<ErasureDto> EraseAccount(Guid id, CancellationToken cancellationToken)
    {
        ErasureDto erasure = await erasures.EraseAccountAsync(id, CurrentAccountId, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.AccountErased, Target(erasure), new { erasure.Number, erasure.State, erasure.Stores }, cancellationToken);
        await PublishIfDoneAsync(erasure);
        return erasure;
    }

    [HttpPost("privacy/people/erasure/preview")]
    [Authorize(Policy = GuardPolicies.Admin)]
    public Task<ErasurePreviewDto> PreviewOutside([FromBody] OutsideErasureInput input, CancellationToken cancellationToken) =>
        erasures.PreviewOutsideAsync(PersonalDataSubject.Outside(input.Email, input.Phone), cancellationToken);

    [HttpPost("privacy/people/erasure")]
    [Authorize(Policy = GuardPolicies.Admin)]
    [StepUp]
    public async Task<ErasureDto> EraseOutside([FromBody] OutsideErasureInput input, CancellationToken cancellationToken)
    {
        ErasureDto erasure = await erasures.EraseOutsideAsync(PersonalDataSubject.Outside(input.Email, input.Phone), CurrentAccountId, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.AddressErased, new AuditTarget("address", null, erasure.Pseudonym),
            new { erasure.Number, erasure.State, erasure.Stores }, cancellationToken);
        return erasure;
    }

    // ---- legal holds ----

    [HttpGet("privacy/holds")]
    [Authorize(Policy = GuardPolicies.Admin)]
    public Task<List<LegalHoldDto>> Holds(CancellationToken cancellationToken) => erasures.HoldsAsync(cancellationToken);

    /// <summary>A hold stops the person's erasure until it's released, so it asks for the password again.</summary>
    [HttpPost("privacy/holds")]
    [Authorize(Policy = GuardPolicies.Admin)]
    [StepUp]
    public async Task<LegalHoldDto> Hold([FromBody] LegalHoldInput input, CancellationToken cancellationToken)
    {
        LegalHoldDto hold = await erasures.HoldAsync(input, CurrentAccountId, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.LegalHoldAdded, HoldTarget(hold), new { hold.Until }, cancellationToken);
        return hold;
    }

    /// <summary>Releasing a hold lets the person be erased again, so it asks for the password.</summary>
    [HttpPost("privacy/holds/{id:guid}/release")]
    [Authorize(Policy = GuardPolicies.Admin)]
    [StepUp]
    public async Task<LegalHoldDto> Release(Guid id, CancellationToken cancellationToken)
    {
        LegalHoldDto hold = await erasures.ReleaseAsync(id, CurrentAccountId, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.LegalHoldReleased, HoldTarget(hold), null, cancellationToken);
        return hold;
    }

    private static AuditTarget Target(ErasureDto erasure) =>
        erasure.AccountId is { } id ? new AuditTarget("Account", id, erasure.State == ErasureStates.Done ? PersonalDataErasures.UsernameOf(erasure.Number) : erasure.About)
            : new AuditTarget("address", null, erasure.Pseudonym);

    private static AuditTarget HoldTarget(LegalHoldDto hold) =>
        hold.AccountId is { } id ? new AuditTarget("Account", id, hold.Username) : new AuditTarget("address", null, hold.Address);

    /// <summary>Tells modules, plugins and webhooks an account is erased: its id and pseudonym, nothing of who it was.</summary>
    private Task PublishIfDoneAsync(ErasureDto erasure) =>
        erasure is { State: ErasureStates.Done, AccountId: { } id } ? PublishAsync([new AccountErasedEto(id, erasure.Pseudonym)]) : Task.CompletedTask;
}
